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
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/command"
	"github.com/stretchr/testify/require"
)

func TestInterruptedInputExitsQuietly(t *testing.T) {
	for _, args := range []string{"query", "query --file -", "api-key revoke automation", "catalog plan -f -", "catalog apply -f -", "catalog apply --plan -"} {
		t.Run(args, func(t *testing.T) {
			reader, writer := io.Pipe()
			defer func() { _ = reader.Close() }()
			defer func() { _ = writer.Close() }()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var out, diagnostics bytes.Buffer
			done := make(chan int, 1)
			go func() {
				done <- execute(ctx, command.Dependencies{
					In: reader, Out: &out, ErrOut: &diagnostics,
					IsInputTerminal: func() bool { return strings.HasPrefix(args, "api-key") },
				}, strings.Fields(args))
			}()
			// Write returns only after the command starts reading; keep the pipe open without a newline or EOF.
			_, err := io.WriteString(writer, "SELECT 1 AS ready")
			require.NoError(t, err)
			cancel()
			select {
			case code := <-done:
				require.Equal(t, clierror.ExitInterrupted, code)
			case <-time.After(5 * time.Second):
				_ = reader.Close()
				<-done
				t.Fatal("command did not stop reading input after cancellation")
			}
			require.Empty(t, out.String())
			if strings.HasPrefix(args, "api-key") {
				require.Equal(t, "Revoke API key automation? [y/N] \n", diagnostics.String())
			} else {
				require.Equal(t, "\n", diagnostics.String())
			}
		})
	}
}

func TestInterruptedQueryReportsStatementOutcome(t *testing.T) {
	const statementID = "01989a4e-4ee2-7e63-87a5-65ac3b5161dc"
	for _, outcome := range []string{"before_submit", "cancelled", "finished", "failed", "running", "unavailable", "malformed"} {
		t.Run(outcome, func(t *testing.T) {
			t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
			t.Setenv("SCOPEDB_CONTROL_URL", "")
			t.Setenv("SCOPEDB_CONSOLE_URL", "")
			t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cancelCalls := 0
			var out, diagnostics bytes.Buffer
			code := execute(ctx, command.Dependencies{
				Out: &out, ErrOut: &diagnostics,
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
				HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					status := http.StatusOK
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
						switch outcome {
						case "unavailable":
							status = http.StatusServiceUnavailable
							body = `{"code":"unavailable","message":"unavailable"}`
						case "malformed":
							body = `{"status":"cancelled"}`
						default:
							body = `{"statement_id":"` + statementID + `","status":"` + outcome + `","created_at":"2026-09-09T00:00:00Z","progress":{}`
							switch outcome {
							case "finished":
								body += `,"result_set":{"metadata":{"fields":[{"name":"ready","data_type":"int"}],"num_rows":1},"format":"json","rows":[["1"]]}`
							case "failed":
								body += `,"error":{"code":"statement_failed","message":"unknown function UNKNOWN_FUNCTION"}`
							}
							body += `}`
						}
					default:
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				})},
			}, []string{"query", "SELECT 1 AS ready"})
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
			switch outcome {
			case "cancelled":
				require.Contains(t, diagnostics.String(), "server cancellation confirmed")
			case "finished":
				require.Contains(t, diagnostics.String(), "statement already completed")
				require.Contains(t, diagnostics.String(), "do not rerun a statement with side effects")
				require.NotContains(t, diagnostics.String(), "could not be confirmed")
			case "failed":
				require.Contains(t, diagnostics.String(), "statement failed: unknown function UNKNOWN_FUNCTION")
				require.NotContains(t, diagnostics.String(), "could not be confirmed")
				require.NotContains(t, diagnostics.String(), "retry")
			default:
				require.Contains(t, diagnostics.String(), "server cancellation could not be confirmed")
				require.Contains(t, diagnostics.String(), "verify the statement's outcome before retrying")
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestInterruptedCatalogWriteReportsUnknownOutcome(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_ENDPOINT", "https://data.example.com")
	t.Setenv("SCOPEDB_API_KEY", "fixture-secret")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var out, diagnostics bytes.Buffer
	writes := 0
	code := execute(ctx, command.Dependencies{
		In: strings.NewReader("databases: []\n"), Out: &out, ErrOut: &diagnostics,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Query().Get("dry_run") == "true" {
				return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"1"`}},
					Body: io.NopCloser(strings.NewReader(`{"before":{"databases":[]},"after":{"databases":[]},"destructive":false}`)), Request: r}, nil
			}
			writes++
			cancel()
			return nil, ctx.Err()
		})},
	}, []string{"catalog", "apply", "-f", "-", "--yes"})
	require.Equal(t, clierror.ExitInterrupted, code)
	require.Equal(t, 1, writes)
	require.Empty(t, out.String())
	require.Contains(t, diagnostics.String(), "catalog_commit_outcome_unknown")
	require.Contains(t, diagnostics.String(), "read the catalog and plan again before retrying")
	require.NotContains(t, diagnostics.String(), "fixture-secret")
}
