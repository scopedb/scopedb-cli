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
	"encoding/json"
	"net/http"
	"testing"

	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/require"
)

func TestListLimitsCapRenderedItems(t *testing.T) {
	store, controlURL := setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/session":
			_, _ = w.Write([]byte(`{"user":{"email":"dev@example.com","status":"active"},"workspaces":[{"id":"ws-1"},{"id":"ws-2"},{"id":"ws-3"}],"current_workspace_id":"ws-1"}`))
		case "GET /api/workspaces/ws-1/api-keys":
			_, _ = w.Write([]byte(`[{"name":"first"},{"name":"second"},{"name":"third"}]`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	require.NoError(t, config.Save(paths, config.Config{
		ControlURL: controlURL, ConsoleURL: config.DefaultConsoleURL, CredentialStore: config.CredentialStorePlaintext,
	}))
	require.NoError(t, store.Save(controlURL, credential.State{SessionToken: "session-secret", WorkspaceID: "ws-1"}))

	for _, args := range [][]string{
		{"workspace", "list", "--format", "json", "--limit", "2"},
		{"api-key", "list", "--format", "json", "--limit", "2"},
	} {
		out, _, err := runCommand(t, args...)
		require.NoError(t, err)
		var items []map[string]any
		require.NoError(t, json.Unmarshal([]byte(out), &items))
		require.Len(t, items, 2)
	}
	out, _, err := runCommand(t, "api-key", "list", "--limit", "1")
	require.NoError(t, err)
	require.Contains(t, out, "first")
	require.NotContains(t, out, "second")

	out, _, err = runCommand(t, "workspace", "list", "--format", "json", "--limit", "0")
	require.NoError(t, err)
	var items []map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &items))
	require.Len(t, items, 3)

	out, _, err = runCommand(t, "api-key", "list", "--limit", "-1")
	require.ErrorContains(t, err, "--limit must not be negative")
	require.Empty(t, out)
}
