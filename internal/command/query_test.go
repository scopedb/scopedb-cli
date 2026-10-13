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
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/stretchr/testify/require"
)

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
