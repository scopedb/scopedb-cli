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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const doctorQueryResult = `{"statement_id":"01989a4e-4ee2-7e63-87a5-65ac3b5161dc","status":"finished","created_at":"2026-09-09T00:00:00Z","progress":{},"result_set":{"metadata":{"fields":[{"name":"ready","data_type":"uint"}],"num_rows":1},"format":"json","rows":[["1"]]}}`

func TestDoctorChecksOAuthDataAccess(t *testing.T) {
	for _, phase := range []struct {
		name           string
		provisioning   string
		queryStatus    int
		exchangeStatus int
		wantDetail     string
	}{
		{"ready", "ready", http.StatusOK, http.StatusOK, ""},
		{"provisioning", "pending", 0, 0, "pending"},
		{"query rejected", "ready", http.StatusUnauthorized, http.StatusOK, "invalid credential"},
		{"exchange rejected", "ready", 0, http.StatusUnauthorized, "scope auth login"},
	} {
		t.Run(phase.name, func(t *testing.T) {
			queries := 0
			data := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				queries++
				assert.Equal(t, "POST /v1/statements", r.Method+" "+r.URL.Path)
				assert.Equal(t, "Bearer data-secret", r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(phase.queryStatus)
				if phase.queryStatus == http.StatusOK {
					_, _ = w.Write([]byte(doctorQueryResult))
				} else {
					_, _ = w.Write([]byte(`{"message":"invalid credential"}`))
				}
			}))
			t.Cleanup(data.Close)

			fake, store := setupCLITest(t)
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
			fake.Details["ws-1"] = controlplane.WorkspaceDetails{
				Workspace:    controlplane.Workspace{ID: "ws-1"},
				Connection:   controlplane.Connection{APIBaseURL: data.URL},
				Provisioning: controlplane.Provisioning{Status: phase.provisioning},
			}
			fake.Exchange = controlplane.TokenExchangeResponse{
				AccessToken: "data-secret", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour).UTC(),
			}
			saveStoredLogin(t, store, fake.URL, "ws-1")
			out, diagnostics, err := runCommandWith(t, Dependencies{
				HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/api/workspaces/ws-1/token-exchange" && phase.exchangeStatus != http.StatusOK {
						header := http.Header{}
						header.Set("Content-Type", "application/json")
						header.Set("X-Request-ID", "exchange-request")
						return &http.Response{
							StatusCode: phase.exchangeStatus,
							Header:     header,
							Body:       io.NopCloser(strings.NewReader(`{"message":"session expired"}`)),
							Request:    r,
						}, nil
					}
					return http.DefaultTransport.RoundTrip(r)
				})},
			}, "--control-url", fake.URL, "doctor", "--format", "json")
			var report doctorReport
			require.NoError(t, json.Unmarshal([]byte(out), &report))
			require.Empty(t, diagnostics)
			require.NotContains(t, out, "data-secret")
			require.Contains(t, report.Checks, doctorCheck{Name: "control plane", Status: "pass", Details: fake.URL})
			if phase.wantDetail == "" {
				require.NoError(t, err)
				require.True(t, report.OK)
				require.Contains(t, report.Checks, doctorCheck{Name: "data plane", Status: "pass", Details: data.URL})
			} else {
				require.Equal(t, clierror.ExitGeneral, clierror.ExitCode(err))
				require.False(t, report.OK)
				require.Contains(t, out, phase.wantDetail)
				require.Equal(t, "fail", report.Checks[len(report.Checks)-1].Status)
			}
			if phase.queryStatus != 0 {
				require.Equal(t, 1, queries)
			} else {
				require.Zero(t, queries)
			}
			if phase.provisioning == "ready" && phase.exchangeStatus == http.StatusOK {
				require.Equal(t, 1, fake.ExchangeCalls)
			} else {
				require.Zero(t, fake.ExchangeCalls)
			}
			if phase.exchangeStatus == http.StatusUnauthorized {
				require.Contains(t, out, "exchange-request")
			}
		})
	}
}

func TestDoctorCheckTimeout(t *testing.T) {
	fake, _ := setupDataPlaneLogin(t, "https://data.example.com")
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "disabled"}[disabled], func(t *testing.T) {
			requests := 0
			root := NewRoot(Dependencies{
				Out: io.Discard, ErrOut: io.Discard,
				HTTPClient: fake.dataClient(func(r *http.Request) (*http.Response, error) {
					requests++
					deadline, ok := r.Context().Deadline()
					if disabled {
						require.False(t, ok)
					} else {
						require.True(t, ok)
						require.InDelta(t, 5, time.Until(deadline).Seconds(), 1)
					}
					return finishedQueryResponse(r), nil
				}),
			})
			args := []string{"doctor"}
			if disabled {
				args = append(args, "--timeout", "0")
			}
			root.SetArgs(args)
			require.NoError(t, root.ExecuteContext(t.Context()))
			require.Equal(t, 1, requests)
		})
	}
}

func TestDoctorTimeoutAndCancellation(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout", true: "interrupt"}[interrupt], func(t *testing.T) {
			fake, _ := setupDataPlaneLogin(t, "https://data.example.com")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var out bytes.Buffer
			root := NewRoot(Dependencies{
				Out: &out,
				HTTPClient: fake.dataClient(func(r *http.Request) (*http.Response, error) {
					if interrupt {
						cancel()
					}
					<-r.Context().Done()
					return nil, r.Context().Err()
				}),
			})
			root.SetArgs([]string{"doctor", "--format", "json", "--timeout", "20ms"})
			err := NormalizeError(root.ExecuteContext(ctx))
			if interrupt {
				require.Equal(t, clierror.ExitInterrupted, clierror.ExitCode(err))
				require.Empty(t, out.String())
			} else {
				require.Equal(t, clierror.ExitGeneral, clierror.ExitCode(err))
				require.Contains(t, out.String(), "operation timed out")
				require.NotContains(t, out.String(), "increase --timeout")
			}
		})
	}
}

func TestDoctorRejectsInvalidTimeout(t *testing.T) {
	for _, timeout := range []string{"-1s"} {
		var out bytes.Buffer
		root := NewRoot(Dependencies{Out: &out, In: strings.NewReader("")})
		root.SetArgs([]string{"doctor", "--timeout", timeout})
		err := NormalizeError(root.ExecuteContext(t.Context()))
		require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
		require.Empty(t, out.String())
	}
}

func TestDoctorGuidesNewUsers(t *testing.T) {
	fake, _ := setupCLITest(t)
	assert.NotEmpty(t, fake.URL)
	for _, format := range []string{"table", "json"} {
		out, diagnostics, err := runCommand(t, "doctor", "--format", format)
		require.NoError(t, err)
		require.Empty(t, diagnostics)
		require.Contains(t, out, "scope auth login")
	}
}

func TestDoctorWarnsUnavailableWorkspace(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-2", "Beta")}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, _, err := runCommand(t, "--control-url", fake.URL, "doctor", "--format", "json")
	require.NoError(t, err)
	require.Contains(t, out, "selected workspace is no longer available")
	require.Contains(t, out, `"status": "warn"`)
	require.Zero(t, fake.ExchangeCalls)
}
