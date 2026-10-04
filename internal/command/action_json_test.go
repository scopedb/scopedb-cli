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
	"net/http"
	"strings"
	"testing"

	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionJSONResults(t *testing.T) {
	currentWorkspace := "ws-1"
	selections, logouts, revocations := 0, 0, 0
	store, controlURL := setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		token := "session-secret"
		if currentWorkspace == "ws-2" {
			token = "rotated-secret"
		}
		assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
		switch r.Method + " " + r.URL.Path {
		case "GET /api/session":
			_, _ = w.Write([]byte(`{"user":{"email":"dev@example.com","status":"active"},"workspaces":[{"id":"ws-1","display_name":"Alpha"},{"id":"ws-2","display_name":"Beta"}],"current_workspace_id":"` + currentWorkspace + `"}`))
		case "POST /api/session/workspace":
			selections++
			currentWorkspace = "ws-2"
			_, _ = w.Write([]byte(`{"token":"rotated-secret","workspace_id":"ws-2"}`))
		case "DELETE /api/workspaces/ws-2/api-keys/automation":
			revocations++
			w.WriteHeader(http.StatusNoContent)
		case "DELETE /api/session":
			logouts++
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	require.NoError(t, config.Save(paths, config.Config{
		ControlURL: controlURL, ConsoleURL: config.DefaultConsoleURL, CredentialStore: config.CredentialStorePlaintext,
	}))
	require.NoError(t, store.Save(controlURL, credential.State{SessionToken: "session-secret", WorkspaceID: "ws-1"}))

	for _, step := range []struct {
		args string
		json string
	}{
		{"workspace use Beta", `{"id":"ws-2","display_name":"Beta","changed":true}`},
		{"workspace use ws-2", `{"id":"ws-2","display_name":"Beta","changed":false}`},
		{"api-key revoke automation --yes", `{"name":"automation","revoked":true}`},
		{"logout", `{"logged_out":true}`},
		{"logout", `{"logged_out":false}`},
	} {
		out, diagnostics, err := runCommand(t, append(strings.Fields(step.args), "--format", "json")...)
		require.NoError(t, err, step.args)
		require.Empty(t, diagnostics, step.args)
		require.JSONEq(t, step.json, out, step.args)
	}
	require.Equal(t, 1, selections)
	require.Equal(t, 1, revocations)
	require.Equal(t, 1, logouts)
	_, err = store.Load(controlURL)
	require.ErrorIs(t, err, credential.ErrNotFound)
}

func TestRevokeJSONCancellation(t *testing.T) {
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In: strings.NewReader("n\n"), Out: &out, ErrOut: &diagnostics,
		IsInputTerminal: func() bool { return true },
		CredentialStore: func(string, config.Paths) (credential.Store, error) {
			t.Fatal("cancellation must not access credentials or call the service")
			return nil, nil
		},
	})
	root.SetArgs([]string{"api-key", "revoke", "automation", "--format", "json"})
	require.NoError(t, root.ExecuteContext(t.Context()))
	require.JSONEq(t, `{"name":"automation","revoked":false}`, out.String())
	require.Contains(t, diagnostics.String(), "Revoke API key")
}

func TestOpenJSONReportsBrowserAction(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_CONSOLE_URL", "https://console.example.com")
	for _, printOnly := range []bool{false, true} {
		var out, diagnostics bytes.Buffer
		var opened string
		root := NewRoot(Dependencies{Out: &out, ErrOut: &diagnostics, OpenURL: func(url string) error {
			opened = url
			return nil
		}})
		args := []string{"open", "query", "--format", "json"}
		want := `{"page":"query","url":"https://console.example.com/query","opened":true}`
		if printOnly {
			args = append(args, "--print")
			want = `{"page":"query","url":"https://console.example.com/query","opened":false}`
		}
		root.SetArgs(args)
		require.NoError(t, root.ExecuteContext(t.Context()))
		require.JSONEq(t, want, out.String())
		require.Empty(t, diagnostics.String())
		if printOnly {
			require.Empty(t, opened)
		} else {
			require.Equal(t, "https://console.example.com/query", opened)
		}
	}
}

func TestVersionJSONAlias(t *testing.T) {
	legacy, _, err := runCommand(t, "version", "--json")
	require.NoError(t, err)
	out, _, err := runCommand(t, "version", "--format", "json")
	require.NoError(t, err)
	require.JSONEq(t, legacy, out)
}
