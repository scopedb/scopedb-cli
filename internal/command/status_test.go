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
	"encoding/json"
	"net/http"
	"testing"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthStatusMachineCredentials(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		key      string
	}{
		{"complete", "https://data.example.com", "machine-secret"},
		{"endpoint only", "https://data.example.com", ""},
		{"key only", "", "machine-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("status must not contact the control plane: %s", r.URL.Path)
				http.NotFound(w, r)
			}))
			for _, format := range []string{"table", "json"} {
				t.Run(format, func(t *testing.T) {
					var out, diagnostics bytes.Buffer
					root := NewRoot(Dependencies{
						Out: &out, ErrOut: &diagnostics,
						Getenv: func(name string) string {
							switch name {
							case "SCOPEDB_ENDPOINT":
								return tc.endpoint
							case "SCOPEDB_API_KEY":
								return tc.key
							default:
								return ""
							}
						},
						CredentialStore: func(string, config.Paths) (credential.Store, error) {
							return doctorUnusedStore{t: t}, nil
						},
						HTTPClient: &http.Client{Transport: doctorTransport(func(r *http.Request) (*http.Response, error) {
							t.Fatalf("status must not make HTTP requests: %s", r.URL)
							return nil, nil
						})},
					})
					root.SetArgs([]string{"auth", "status", "--format", format})
					err := root.ExecuteContext(t.Context())
					require.NotContains(t, out.String()+diagnostics.String()+clierror.Render(err), "machine-secret")
					require.Empty(t, diagnostics.String())
					if tc.endpoint == "" || tc.key == "" {
						require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
						require.Empty(t, out.String())
						return
					}
					require.NoError(t, err)
					if format == "json" {
						require.JSONEq(t, `{"auth_mode":"api_key","credential_source":"environment","endpoint":"https://data.example.com"}`, out.String())
					} else {
						require.Contains(t, out.String(), "environment")
						require.Contains(t, out.String(), tc.endpoint)
						require.NotContains(t, out.String(), "Provisioning")
					}
				})
			}
		})
	}
}

func TestAuthStatusSession(t *testing.T) {
	for _, source := range []string{config.CredentialStoreKeyring, config.CredentialStorePlaintext} {
		t.Run(source, func(t *testing.T) {
			var requests []string
			store, controlURL := setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.Method+" "+r.URL.Path)
				assert.Equal(t, "Bearer session-secret", r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "application/json")
				switch r.Method + " " + r.URL.Path {
				case "GET /api/session":
					_, _ = w.Write([]byte(`{"user":{"email":"dev@example.com","status":"active"},"current_workspace_id":"ws-1"}`))
				case "GET /api/workspaces/ws-1":
					_, _ = w.Write([]byte(`{"workspace":{"id":"ws-1","display_name":"Analytics"},"connection":{"api_base_url":"https://data.example.com"},"provisioning":{"status":"pending"}}`))
				default:
					t.Errorf("status must not check query access: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			t.Setenv("SCOPEDB_CREDENTIAL_STORE", source)
			require.NoError(t, store.Save(controlURL, credential.State{SessionToken: "session-secret", WorkspaceID: "ws-1"}))
			for _, format := range []string{"table", "json"} {
				requests = nil
				var out, diagnostics bytes.Buffer
				root := NewRoot(Dependencies{
					Out: &out, ErrOut: &diagnostics,
					Getenv:          func(string) string { return "" },
					CredentialStore: func(string, config.Paths) (credential.Store, error) { return store, nil },
				})
				root.SetArgs([]string{"auth", "status", "--format", format})
				require.NoError(t, root.ExecuteContext(t.Context()))
				require.Empty(t, diagnostics.String())
				require.Equal(t, []string{"GET /api/session", "GET /api/workspaces/ws-1"}, requests)
				require.NotContains(t, out.String(), "session-secret")
				require.NotContains(t, out.String(), "pending")
				if format == "json" {
					expected, err := json.Marshal(map[string]string{
						"auth_mode": "session", "credential_source": source, "control_url": controlURL,
						"email": "dev@example.com", "user_status": "active", "workspace_id": "ws-1",
						"workspace_name": "Analytics", "endpoint": "https://data.example.com",
					})
					require.NoError(t, err)
					require.JSONEq(t, string(expected), out.String())
				} else {
					require.Contains(t, out.String(), source)
					require.Contains(t, out.String(), "dev@example.com")
				}
			}
		})
	}
}
