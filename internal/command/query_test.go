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

package command

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/stretchr/testify/require"
)

func TestQueryChecksOutputBeforeSubmission(t *testing.T) {
	for _, destination := range []string{"existing_file", "missing_parent", "directory_with_force", "dangling_symlink"} {
		t.Run(destination, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "result.json")
			args := []string{"--output", path, "--format", "json"}
			switch destination {
			case "existing_file":
				require.NoError(t, os.WriteFile(path, []byte("original"), 0o600))
			case "missing_parent":
				path = filepath.Join(directory, "missing", "result.json")
				args[1] = path
			case "directory_with_force":
				require.NoError(t, os.Mkdir(path, 0o700))
				args = append(args, "--force")
			case "dangling_symlink":
				if runtime.GOOS == "windows" {
					t.Skip("creating symlinks requires elevated privileges on Windows")
				}
				require.NoError(t, os.Symlink(filepath.Join(directory, "missing"), path))
			}
			submissions := 0
			out, err := runQueryWithTransport(t, func(r *http.Request) (*http.Response, error) {
				submissions++
				return finishedQueryResponse(r), nil
			}, args...)
			require.Error(t, err)
			require.Zero(t, submissions, "invalid output must not execute a statement")
			require.Empty(t, out)
			if destination == "existing_file" {
				data, readErr := os.ReadFile(path)
				require.NoError(t, readErr)
				require.Equal(t, "original", string(data))
			}
		})
	}
}

func TestQueryReportsCompletionWhenOutputIsCreatedConcurrently(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "result.json")
	submissions := 0
	out, err := runQueryWithTransport(t, func(r *http.Request) (*http.Response, error) {
		require.Equal(t, "POST /v1/statements", r.Method+" "+r.URL.Path)
		submissions++
		require.NoError(t, os.WriteFile(path, []byte("concurrent output"), 0o600))
		return finishedQueryResponse(r), nil
	}, "--output", path, "--format", "json")
	require.Error(t, err)
	require.Equal(t, 1, submissions)
	require.Empty(t, out)
	rendered := clierror.Render(err)
	require.Contains(t, rendered, "query 01989a4e-4ee2-7e63-87a5-65ac3b5161dc completed")
	require.Contains(t, rendered, "do not rerun a statement with side effects")
	require.NotContains(t, rendered, "pass --force")
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, "concurrent output", string(data))
	entries, readErr := os.ReadDir(directory)
	require.NoError(t, readErr)
	require.Len(t, entries, 1, "temporary output must be removed")
}

func TestQueryWritesOutputAndAllowsExplicitOverwrite(t *testing.T) {
	for _, force := range []bool{false, true} {
		directory := t.TempDir()
		path := filepath.Join(directory, "result.json")
		args := []string{"--output", path, "--format", "json"}
		if force {
			require.NoError(t, os.WriteFile(path, []byte("original"), 0o600))
			args = append(args, "--force")
		}
		out, err := runQueryWithTransport(t, func(r *http.Request) (*http.Response, error) {
			return finishedQueryResponse(r), nil
		}, args...)
		require.NoError(t, err)
		require.Empty(t, out)
		data, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		require.JSONEq(t, `[{"ready":1}]`, string(data))
		entries, readErr := os.ReadDir(directory)
		require.NoError(t, readErr)
		require.Len(t, entries, 1, "temporary output must be removed")
	}
}

func TestQueryFailurePreservesExistingOutput(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "result.json")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o600))
	_, err := runQueryWithTransport(t, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("fixture query failure")
	}, "--output", path, "--force")
	require.ErrorContains(t, err, "fixture query failure")
	require.NotContains(t, clierror.Render(err), "completed")
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, "original", string(data))
	entries, readErr := os.ReadDir(directory)
	require.NoError(t, readErr)
	require.Len(t, entries, 1, "temporary output must be removed")
}

func runQueryWithTransport(t *testing.T, transport doctorTransport, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runQueryWithWriter(t, transport, &out, args...)
	require.NotContains(t, out.String(), "fixture-secret")
	return out.String(), err
}

func runQueryWithWriter(t *testing.T, transport doctorTransport, out io.Writer, args ...string) error {
	t.Helper()
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_CONTROL_URL", "")
	t.Setenv("SCOPEDB_CONSOLE_URL", "")
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")
	var diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		Out: out, ErrOut: &diagnostics,
		Getenv: func(name string) string {
			switch name {
			case "SCOPEDB_ENDPOINT":
				return "https://data.example.com"
			case "SCOPEDB_API_KEY":
				return "fixture-secret"
			default:
				return ""
			}
		},
		HTTPClient: &http.Client{Transport: transport},
	})
	root.SetArgs(append([]string{"query", "SELECT 1 AS ready"}, args...))
	err := root.ExecuteContext(t.Context())
	require.NotContains(t, diagnostics.String()+clierror.Render(err), "fixture-secret")
	return err
}

func finishedQueryResponse(r *http.Request) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"statement_id":"01989a4e-4ee2-7e63-87a5-65ac3b5161dc","status":"finished","created_at":"2026-09-09T00:00:00Z","progress":{},"result_set":{"metadata":{"fields":[{"name":"ready","data_type":"int"}],"num_rows":1},"format":"json","rows":[["1"]]}}`)),
		Request:    r,
	}
}

func TestQueryReportsCompletionWhenStdoutFails(t *testing.T) {
	for _, format := range []string{"table", "json", "jsonl", "csv"} {
		t.Run(format, func(t *testing.T) {
			writeErr := errors.New("output is full")
			submissions := 0
			err := runQueryWithWriter(t, func(r *http.Request) (*http.Response, error) {
				require.Equal(t, "POST /v1/statements", r.Method+" "+r.URL.Path)
				submissions++
				return finishedQueryResponse(r), nil
			}, failingWriter{writeErr}, "--format", format)
			require.ErrorIs(t, err, writeErr)
			require.Equal(t, clierror.ExitGeneral, clierror.ExitCode(err))
			require.Equal(t, 1, submissions)
			require.Contains(t, clierror.Render(err), "query 01989a4e-4ee2-7e63-87a5-65ac3b5161dc completed")
			require.Contains(t, clierror.Render(err), "do not rerun a statement with side effects")
		})
	}
}

func TestQueryTimeoutReportsServerCancellation(t *testing.T) {
	const statementID = "01989a4e-4ee2-7e63-87a5-65ac3b5161dc"
	for _, cancelStatus := range []string{"cancelled", "finished", "failed", "running", "unavailable"} {
		t.Run(cancelStatus, func(t *testing.T) {
			t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
			t.Setenv("SCOPEDB_CONTROL_URL", "")
			t.Setenv("SCOPEDB_CONSOLE_URL", "")
			t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")
			cancelCalls := 0
			var out, diagnostics bytes.Buffer
			root := NewRoot(Dependencies{
				Out: &out, ErrOut: &diagnostics,
				Getenv: func(name string) string {
					if name == "SCOPEDB_ENDPOINT" {
						return "https://data.example.com"
					}
					if name == "SCOPEDB_API_KEY" {
						return "fixture-secret"
					}
					return ""
				},
				HTTPClient: &http.Client{Transport: doctorTransport(func(r *http.Request) (*http.Response, error) {
					status := http.StatusOK
					body := `{"statement_id":"` + statementID + `","status":"running","created_at":"2026-09-09T00:00:00Z","progress":{}}`
					switch r.Method + " " + r.URL.Path {
					case "POST /v1/statements":
					case "GET /v1/statements/" + statementID:
						return nil, context.DeadlineExceeded
					case "POST /v1/statements/" + statementID + "/cancel":
						cancelCalls++
						require.NoError(t, r.Context().Err(), "server cancellation must have a fresh context")
						if cancelStatus != "unavailable" {
							body = `{"statement_id":"` + statementID + `","status":"` + cancelStatus + `","created_at":"2026-09-09T00:00:00Z","message":"fixture cancellation result"}`
						} else {
							status = http.StatusServiceUnavailable
							body = `{"message":"unavailable"}`
						}
					default:
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
						status = http.StatusNotFound
					}
					return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				})},
			})
			root.SetArgs([]string{"query", "SELECT 1 AS ready"})
			err := root.ExecuteContext(t.Context())
			require.Equal(t, clierror.ExitTemporary, clierror.ExitCode(err))
			require.Equal(t, 1, cancelCalls)
			require.Empty(t, out.String())
			rendered := clierror.Render(err)
			require.Contains(t, rendered, statementID)
			require.NotContains(t, rendered+diagnostics.String(), "fixture-secret")
			if cancelStatus == "cancelled" {
				require.Contains(t, rendered, "increase --timeout")
				require.NotContains(t, rendered, "could not be confirmed")
			} else {
				require.Contains(t, rendered, "server cancellation could not be confirmed")
				require.Contains(t, rendered, "verify the statement's outcome before retrying")
				require.NotContains(t, rendered, "increase --timeout and retry")
			}
		})
	}
}

func TestQueryOutputFileHasRestrictedPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file permissions use ACLs")
	}
	path := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, writeResultFile(path, false, func(w io.Writer) error {
		_, err := io.WriteString(w, `[{"email":"private@example.com"}]`)
		return err
	}))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}
