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

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/command"
	"github.com/stretchr/testify/require"
)

func TestInterruptedQueryReportsStatementOutcome(t *testing.T) {
	const statementID = "01989a4e-4ee2-7e63-87a5-65ac3b5161dc"
	for _, outcome := range []string{"before_submit", "cancelled", "finished", "unavailable"} {
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
						if outcome == "unavailable" {
							status = http.StatusServiceUnavailable
							body = `{"message":"unavailable"}`
						} else {
							body = `{"statement_id":"` + statementID + `","status":"` + outcome + `","created_at":"2026-09-09T00:00:00Z","message":"fixture cancellation result"}`
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
			if outcome == "cancelled" {
				require.Contains(t, diagnostics.String(), "server cancellation confirmed")
			} else {
				require.Contains(t, diagnostics.String(), "server cancellation could not be confirmed")
				require.Contains(t, diagnostics.String(), "verify the statement's outcome before retrying")
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
