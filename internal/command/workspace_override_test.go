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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceOverrideUsesTargetWithoutChangingSelection(t *testing.T) {
	t.Setenv("SCOPEDB_ENDPOINT", "")
	t.Setenv("SCOPEDB_API_KEY", "")
	var controlURL string
	var switched atomic.Bool
	store, url := setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/statements" {
			assert.Equal(t, "Bearer session-secret", r.Header.Get("Authorization"))
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/session":
			_, _ = w.Write([]byte(`{"user":{"email":"dev@example.com","status":"active"},"workspaces":[{"id":"ws-1","display_name":"Alpha"},{"id":"ws-2","display_name":"Beta"}],"current_workspace_id":""}`))
		case "GET /api/workspaces/ws-2":
			_, _ = w.Write([]byte(`{"workspace":{"id":"ws-2","display_name":"Beta"},"connection":{"api_base_url":"` + controlURL + `"},"provisioning":{"status":"ready"}}`))
		case "POST /api/workspaces/ws-2/token-exchange":
			_, _ = w.Write([]byte(`{"access_token":"data-secret","token_type":"Bearer","expires_at":"2099-01-01T00:00:00Z"}`))
		case "POST /v1/statements":
			assert.Equal(t, "Bearer data-secret", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"statement_id":"01989a4e-4ee2-7e63-87a5-65ac3b5161dc","status":"finished","created_at":"2026-09-09T00:00:00Z","progress":{},"result_set":{"metadata":{"fields":[{"name":"ready","data_type":"u_int"}],"num_rows":1},"format":"json","rows":[["1"]]}}`))
		case "GET /api/workspaces/ws-2/api-keys":
			_, _ = w.Write([]byte(`[{"name":"automation"}]`))
		case "POST /api/workspaces/ws-2/api-keys":
			_, _ = w.Write([]byte(`{"name":"new-key","key":"once-secret"}`))
		case "DELETE /api/workspaces/ws-2/api-keys/automation":
			w.WriteHeader(http.StatusNoContent)
		case "POST /api/session/workspace":
			switched.Store(true)
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	controlURL = url
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	require.NoError(t, config.Save(paths, config.Config{
		ControlURL: controlURL, ConsoleURL: config.DefaultConsoleURL, CredentialStore: config.CredentialStorePlaintext,
	}))
	require.NoError(t, store.Save(controlURL, credential.State{SessionToken: "session-secret"}))

	out, _, err := runCommand(t, "query", "SELECT 1 AS ready", "--workspace", "Beta", "--format", "json")
	require.NoError(t, err)
	require.Contains(t, out, "ready")

	out, _, err = runCommand(t, "workspace", "show", "--workspace", "ws-2", "--format", "json")
	require.NoError(t, err)
	var details map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &details))
	require.Equal(t, "ws-2", details["workspace"].(map[string]any)["id"])

	out, _, err = runCommand(t, "api-key", "list", "--workspace", "Beta", "--format", "json")
	require.NoError(t, err)
	require.Contains(t, out, "automation")

	out, _, err = runCommand(t, "api-key", "create", "new-key", "--workspace", "ws-2", "--format", "json")
	require.NoError(t, err)
	require.Contains(t, out, "once-secret")

	out, _, err = runCommand(t, "api-key", "revoke", "automation", "--yes", "--workspace", "ws-2", "--format", "json")
	require.NoError(t, err)
	require.Contains(t, out, `"revoked": true`)

	state, err := store.Load(controlURL)
	require.NoError(t, err)
	require.Equal(t, "session-secret", state.SessionToken)
	require.Empty(t, state.WorkspaceID)
	require.Empty(t, state.DataToken)
	require.False(t, switched.Load())
}

func TestWorkspaceOverrideRejectsMachineCredentialsAndEmptyTarget(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_ENDPOINT", "https://data.example.com")
	t.Setenv("SCOPEDB_API_KEY", "machine-secret")
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{In: strings.NewReader(""), Out: &out, ErrOut: &diagnostics})
	root.SetArgs([]string{"query", "SELECT 1 AS ready", "--workspace", "ws-2"})
	err := root.ExecuteContext(t.Context())
	require.ErrorContains(t, err, "--workspace cannot be combined")
	require.Empty(t, out.String())

	text, _, err := runCommand(t, "api-key", "list", "--workspace", "")
	require.ErrorContains(t, err, "--workspace must not be empty")
	require.Empty(t, text)
}
