// Copyright 2026 ScopeDB, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/command"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/require"
)

func TestCommandErrorsAtProcessBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		cause   error
		code    int
		message string
	}{
		{name: "forbidden", status: http.StatusForbidden, code: clierror.ExitAuth, message: "access denied"},
		{name: "missing", status: http.StatusNotFound, code: clierror.ExitNotFound, message: "access denied"},
		{name: "unavailable", status: http.StatusServiceUnavailable, code: clierror.ExitTemporary, message: "access denied"},
		{name: "timeout", cause: context.DeadlineExceeded, code: clierror.ExitTemporary, message: "operation timed out"},
		{name: "transport", cause: errors.New("connection refused"), code: clierror.ExitTemporary, message: "connection refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SCOPEDB_HOME", t.TempDir())
			const controlURL = "https://control.example.com"
			store := credential.NewPlaintextStore(filepath.Join(t.TempDir(), "credentials.json"))
			require.NoError(t, store.Save(controlURL, credential.State{
				AccessToken: "fixture-token", AccessTokenExpiresAt: time.Now().Add(time.Hour),
				RefreshToken: "fixture-refresh", WorkspaceID: "ws-1",
			}))
			var out, diagnostics bytes.Buffer
			code := execute(t.Context(), command.Dependencies{
				Out: &out, ErrOut: &diagnostics, Getenv: func(string) string { return "" },
				CredentialStore: func(string, config.Paths) (credential.Store, error) { return store, nil },
				HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if tc.cause != nil {
						return nil, tc.cause
					}
					return &http.Response{
						StatusCode: tc.status, Request: r,
						Header: http.Header{"X-Request-Id": []string{"request-1"}},
						Body:   io.NopCloser(strings.NewReader(`{"error":{"message":"access denied"}}`)),
					}, nil
				})},
			}, []string{"--control-url", controlURL, "workspace", "list"})
			require.Equal(t, tc.code, code)
			require.Empty(t, out.String())
			require.Equal(t, 1, strings.Count(diagnostics.String(), "Error:"))
			require.Contains(t, diagnostics.String(), tc.message)
			if tc.cause == nil {
				require.Contains(t, diagnostics.String(), "request-1")
			}
			if tc.code == clierror.ExitAuth {
				require.Equal(t, 1, strings.Count(diagnostics.String(), "scope auth login"))
			}
			if errors.Is(tc.cause, context.DeadlineExceeded) {
				require.NotContains(t, diagnostics.String(), "--timeout")
				require.NotContains(t, diagnostics.String(), "--request-timeout")
			}
			require.NotContains(t, diagnostics.String(), "fixture-token")
			require.NotContains(t, diagnostics.String(), "fixture-refresh")
		})
	}
}

func TestInterruptedInputExitsQuietly(t *testing.T) {
	reader, writer := io.Pipe()
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var out, diagnostics bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, command.Dependencies{In: reader, Out: &out, ErrOut: &diagnostics}, []string{"query"})
	}()
	// A completed write proves the command reached stdin; leave it blocked without a newline.
	writeDone := make(chan error, 1)
	go func() {
		_, err := io.WriteString(writer, "SELECT 1 AS ready")
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		require.NoError(t, err)
	case code := <-done:
		t.Fatalf("command exited before reading input: %d", code)
	case <-time.After(5 * time.Second):
		t.Fatal("command did not begin reading input")
	}
	cancel()
	select {
	case code := <-done:
		require.Equal(t, clierror.ExitInterrupted, code)
	case <-time.After(5 * time.Second):
		t.Fatal("command did not stop reading input")
	}
	require.Empty(t, out.String())
	require.Equal(t, "\n", diagnostics.String())
}

func TestInterruptedQueryReportsStatementOutcome(t *testing.T) {
	const statementID = "01989a4e-4ee2-7e63-87a5-65ac3b5161dc"
	for _, outcome := range []string{"before_submit", "finished"} {
		t.Run(outcome, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cancelCalls := 0
			var out, diagnostics bytes.Buffer
			deps := loginDependencies(t, func(r *http.Request) (*http.Response, error) {
				body := `{"statement_id":"` + statementID + `","status":"running","created_at":"2026-09-09T00:00:00Z","progress":{}}`
				switch r.Method + " " + r.URL.Path {
				case "POST /v1/statements":
					if outcome == "before_submit" {
						cancel()
						return nil, ctx.Err()
					}
				case "GET /v1/statements/" + statementID:
					cancel()
					return nil, ctx.Err()
				case "POST /v1/statements/" + statementID + "/cancel":
					cancelCalls++
					require.NoError(t, r.Context().Err(), "cancellation must use a fresh context")
					require.Equal(t, "json", r.URL.Query().Get("format"))
					body = `{"statement_id":"` + statementID + `","status":"finished","created_at":"2026-09-09T00:00:00Z","progress":{},"result_set":{"metadata":{"fields":[{"name":"ready","data_type":"int"}],"num_rows":1},"format":"json","rows":[["1"]]}}`
				default:
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			deps.Out, deps.ErrOut = &out, &diagnostics
			code := execute(ctx, deps, []string{"query", "SELECT 1 AS ready"})
			require.Equal(t, clierror.ExitInterrupted, code)
			require.Empty(t, out.String())
			if outcome == "before_submit" {
				require.Zero(t, cancelCalls)
				require.Equal(t, "\n", diagnostics.String())
				return
			}
			require.Equal(t, 1, cancelCalls)
			require.Contains(t, diagnostics.String(), statementID)
			require.NotContains(t, diagnostics.String(), "fixture-secret")
			require.Contains(t, diagnostics.String(), "statement already completed")
			require.Contains(t, diagnostics.String(), "do not rerun a statement with side effects")
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestInterruptedCatalogWriteReportsUnknownOutcome(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var out, diagnostics bytes.Buffer
	writes := 0
	deps := loginDependencies(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("dry_run") == "true" {
			return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"1"`}},
				Body: io.NopCloser(strings.NewReader(`{"before":{"databases":[]},"after":{"databases":[]},"destructive":false}`)), Request: r}, nil
		}
		writes++
		cancel()
		return nil, ctx.Err()
	})
	deps.In, deps.Out, deps.ErrOut = strings.NewReader("databases: []\n"), &out, &diagnostics
	code := execute(ctx, deps, []string{"catalog", "apply", "-f", "-", "--yes"})
	require.Equal(t, clierror.ExitInterrupted, code)
	require.Equal(t, 1, writes)
	require.Empty(t, out.String())
	require.Contains(t, diagnostics.String(), "catalog_commit_outcome_unknown")
	require.Contains(t, diagnostics.String(), "read the catalog and plan again before retrying")
	require.NotContains(t, diagnostics.String(), "fixture-secret")
}

func loginDependencies(t *testing.T, data roundTripFunc) command.Dependencies {
	t.Helper()
	const controlURL = "https://control.example.com"
	t.Setenv("SCOPEDB_HOME", t.TempDir())
	t.Setenv("SCOPEDB_CONTROL_URL", controlURL)
	store := credential.NewPlaintextStore(filepath.Join(t.TempDir(), "credentials.json"))
	require.NoError(t, store.Save(controlURL, credential.State{
		AccessToken: "fixture-token", AccessTokenExpiresAt: time.Now().Add(time.Hour),
		RefreshToken: "fixture-refresh", WorkspaceID: "ws-1",
		DataToken: "fixture-secret", DataTokenWorkspaceID: "ws-1", DataTokenExpiresAt: time.Now().Add(time.Hour),
	}))
	control := map[string]string{
		"/api/user":            `{"id":"user-1","email":"dev@example.com","status":"active"}`,
		"/api/workspaces":      `{"workspaces":[{"id":"ws-1","provisioning_status":"ready"}]}`,
		"/api/workspaces/ws-1": `{"workspace":{"id":"ws-1"},"connection":{"api_base_url":"https://data.example.com"},"provisioning":{"status":"ready"}}`,
	}
	return command.Dependencies{
		CredentialStore: func(string, config.Paths) (credential.Store, error) { return store, nil },
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "data.example.com" {
				body, ok := control[r.URL.Path]
				require.True(t, ok, "unexpected control-plane request: %s", r.URL)
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			}
			return data(r)
		})},
	}
}
