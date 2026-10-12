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

	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceGetJSON(t *testing.T) {
	for _, tc := range []struct {
		name        string
		displayName string
		updatedAt   string
	}{
		{"populated", `"Analytics"`, `"2026-09-15T00:00:00Z"`},
		{"nullable", "null", "null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, controlURL := setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "Bearer session-secret", r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "application/json")
				switch r.Method + " " + r.URL.Path {
				case "GET /api/session":
					_, _ = w.Write([]byte(`{"user":{"email":"dev@example.com","status":"active"},"current_workspace_id":"ws-1"}`))
				case "GET /api/workspaces/ws-1":
					_, _ = w.Write([]byte(`{"workspace":{"id":"ws-1","display_name":` + tc.displayName + `},"connection":{"api_base_url":"https://data.example.com","auth_scheme":"Bearer"},"placement":{"provider":"aws","region":"us-east-1"},"provisioning":{"status":"pending","updated_at":` + tc.updatedAt + `}}`))
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			t.Setenv("SCOPEDB_CREDENTIAL_STORE", config.CredentialStorePlaintext)
			require.NoError(t, store.Save(controlURL, credential.State{SessionToken: "session-secret", WorkspaceID: "ws-1"}))
			out, diagnostics, err := runCommand(t, "workspace", "get", "--format", "json")
			require.NoError(t, err)
			require.Empty(t, diagnostics)
			require.JSONEq(t, `{"workspace":{"id":"ws-1","display_name":`+tc.displayName+`},"connection":{"endpoint":"https://data.example.com","auth_scheme":"Bearer"},"placement":{"provider":"aws","region":"us-east-1"},"provisioning":{"status":"pending","updated_at":`+tc.updatedAt+`}}`, out)
		})
	}
}

func TestWorkspaceUseMachineOverride(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		key      string
		warning  string
	}{
		{"login", "", "", ""},
		{"machine", "https://machine.example.com", "machine-secret", "still use SCOPEDB_ENDPOINT and SCOPEDB_API_KEY"},
		{"endpoint only", "https://machine.example.com", "", "require both SCOPEDB_ENDPOINT and SCOPEDB_API_KEY"},
		{"key only", "", "machine-secret", "require both SCOPEDB_ENDPOINT and SCOPEDB_API_KEY"},
	} {
		for _, format := range []string{"text", "json"} {
			t.Run(tc.name+" "+format, func(t *testing.T) {
				current := "ws-1"
				selections := 0
				store, controlURL := setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					token := "session-secret"
					if current == "ws-2" {
						token = "rotated-secret"
					}
					assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
					w.Header().Set("Content-Type", "application/json")
					switch r.Method + " " + r.URL.Path {
					case "GET /api/session":
						_, _ = w.Write([]byte(`{"user":{"email":"dev@example.com","status":"active"},"workspaces":[{"id":"ws-1"},{"id":"ws-2","display_name":"Beta"}],"current_workspace_id":"` + current + `"}`))
					case "POST /api/session/workspace":
						var body map[string]string
						assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
						assert.Equal(t, "ws-2", body["workspace_id"])
						selections++
						current = "ws-2"
						_, _ = w.Write([]byte(`{"token":"rotated-secret","workspace_id":"ws-2"}`))
					default:
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
						http.NotFound(w, r)
					}
				}))
				t.Setenv("SCOPEDB_CREDENTIAL_STORE", config.CredentialStorePlaintext)
				require.NoError(t, store.Save(controlURL, credential.State{SessionToken: "session-secret", WorkspaceID: "ws-1", DataToken: "cached-secret"}))
				for _, changed := range []bool{true, false} {
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
					})
					root.SetArgs([]string{"workspace", "use", "Beta", "--format", format})
					require.NoError(t, root.ExecuteContext(t.Context()))
					if tc.warning == "" {
						require.Empty(t, diagnostics.String())
					} else {
						require.Contains(t, diagnostics.String(), tc.warning)
					}
					require.NotContains(t, out.String(), "Warning")
					for _, secret := range []string{"machine-secret", "session-secret", "rotated-secret", "cached-secret"} {
						require.NotContains(t, out.String()+diagnostics.String(), secret)
					}
					if format == "json" {
						var result workspaceUseResult
						require.NoError(t, json.Unmarshal(out.Bytes(), &result))
						require.Equal(t, "ws-2", result.ID)
						require.Equal(t, changed, result.Changed)
					} else {
						require.Contains(t, out.String(), "for your login session")
					}
					state, err := store.Load(controlURL)
					require.NoError(t, err)
					require.Equal(t, "rotated-secret", state.SessionToken)
					require.Equal(t, "ws-2", state.WorkspaceID)
					require.Empty(t, state.DataToken)
				}
				require.Equal(t, 1, selections)
			})
		}
	}
}
