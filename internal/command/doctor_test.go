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
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const doctorQueryResult = `{"statement_id":"01989a4e-4ee2-7e63-87a5-65ac3b5161dc","status":"finished","created_at":"2026-09-09T00:00:00Z","progress":{},"result_set":{"metadata":{"fields":[{"name":"ready","data_type":"u_int"}],"num_rows":1},"format":"json","rows":[["1"]]}}`

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

			var out, diagnostics bytes.Buffer
			root := NewRoot(Dependencies{
				Out: &out, ErrOut: &diagnostics,
				Getenv: func(string) string { return "" },
				Sleep:  func(time.Duration) {},
				HTTPClient: &http.Client{Transport: doctorTransport(func(r *http.Request) (*http.Response, error) {
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
			})
			root.SetArgs([]string{"--control-url", fake.URL, "doctor", "--format", "json"})
			err := root.ExecuteContext(t.Context())
			var report doctorReport
			require.NoError(t, json.Unmarshal(out.Bytes(), &report))
			require.Empty(t, diagnostics.String())
			require.NotContains(t, out.String(), "data-secret")
			if phase.wantDetail == "" {
				require.NoError(t, err)
				require.True(t, report.OK)
				require.Contains(t, report.Checks, doctorCheck{Name: "data plane", Status: "pass", Details: data.URL})
			} else {
				require.Equal(t, clierror.ExitGeneral, clierror.ExitCode(err))
				require.False(t, report.OK)
				require.Contains(t, out.String(), phase.wantDetail)
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
				require.Contains(t, out.String(), "exchange-request")
			}
		})
	}
}

func TestDoctorMachineCredentials(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		key    string
		status int
		want   string
	}{
		{"valid", "machine-secret", http.StatusOK, ""},
		{"unauthorized", "machine-secret", http.StatusUnauthorized, "same workspace"},
		{"partial", "", 0, "must be set together"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				assert.Equal(t, "Bearer machine-secret", r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(scenario.status)
				if scenario.status == http.StatusOK {
					_, _ = w.Write([]byte(doctorQueryResult))
				} else {
					_, _ = w.Write([]byte(`{"message":"invalid credential"}`))
				}
			}))
			t.Cleanup(server.Close)
			var out, diagnostics bytes.Buffer
			root := NewRoot(Dependencies{
				Out: &out, ErrOut: &diagnostics,
				Getenv: func(name string) string {
					if name == "SCOPEDB_ENDPOINT" {
						return server.URL
					}
					if name == "SCOPEDB_API_KEY" {
						return scenario.key
					}
					return ""
				},
				CredentialStore: func(string, config.Paths) (credential.Store, error) {
					return doctorUnusedStore{t: t}, nil
				},
			})
			root.SetArgs([]string{"doctor", "--format", "json"})
			err := root.ExecuteContext(t.Context())
			var report doctorReport
			require.NoError(t, json.Unmarshal(out.Bytes(), &report))
			require.NotContains(t, out.String()+diagnostics.String(), "machine-secret")
			require.Empty(t, diagnostics.String())
			if scenario.want == "" {
				require.NoError(t, err)
				require.True(t, report.OK)
			} else {
				require.Equal(t, clierror.ExitGeneral, clierror.ExitCode(err))
				require.False(t, report.OK)
				require.Contains(t, out.String(), scenario.want)
			}
			if scenario.key == "" {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
		})
	}
}

type doctorUnusedStore struct{ t *testing.T }

func (s doctorUnusedStore) Load(string) (credential.State, error) {
	s.t.Error("machine mode must not load human credentials")
	return credential.State{}, credential.ErrNotFound
}
func (s doctorUnusedStore) Save(string, credential.State) error {
	s.t.Error("machine mode must not save human credentials")
	return nil
}
func (s doctorUnusedStore) Delete(string) error {
	s.t.Error("machine mode must not delete human credentials")
	return nil
}

type doctorTransport func(*http.Request) (*http.Response, error)

func (f doctorTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDoctorTimeoutAndCancellation(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout", true: "interrupt"}[interrupt], func(t *testing.T) {
			t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var out bytes.Buffer
			root := NewRoot(Dependencies{
				Out: &out,
				Getenv: func(name string) string {
					if name == "SCOPEDB_ENDPOINT" {
						return "https://data.example.com"
					}
					if name == "SCOPEDB_API_KEY" {
						return "machine-secret"
					}
					return ""
				},
				HTTPClient: &http.Client{Transport: doctorTransport(func(r *http.Request) (*http.Response, error) {
					if interrupt {
						cancel()
					}
					<-r.Context().Done()
					return nil, r.Context().Err()
				})},
			})
			root.SetArgs([]string{"doctor", "--format", "json", "--timeout", "20ms"})
			err := root.ExecuteContext(ctx)
			if interrupt {
				require.Equal(t, clierror.ExitInterrupted, clierror.ExitCode(err))
				require.Empty(t, out.String())
			} else {
				require.Equal(t, clierror.ExitGeneral, clierror.ExitCode(err))
				require.Contains(t, out.String(), "operation timed out")
				require.Contains(t, out.String(), "increase --timeout")
			}
		})
	}
}

func TestDoctorRejectsInvalidTimeout(t *testing.T) {
	for _, timeout := range []string{"-1s"} {
		var out bytes.Buffer
		root := NewRoot(Dependencies{Out: &out, In: strings.NewReader("")})
		root.SetArgs([]string{"doctor", "--timeout", timeout})
		err := root.ExecuteContext(t.Context())
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
		require.Contains(t, out, "SCOPEDB_ENDPOINT and SCOPEDB_API_KEY")
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
