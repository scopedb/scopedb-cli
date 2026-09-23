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
	"testing"

	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/require"
)

func TestDisabledPromptsRequireExplicitInput(t *testing.T) {
	_, _ = setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/login":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"login_challenge":"challenge-secret"}`))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	t.Setenv("SCOPEDB_PROMPT_DISABLED", "1")
	for _, args := range [][]string{
		{"login"},
		{"login", "--email", "dev@example.com"},
		{"api-key", "revoke", "automation"},
	} {
		var out, diagnostics bytes.Buffer
		root := NewRoot(Dependencies{
			In: strings.NewReader("123456\n"), Out: &out, ErrOut: &diagnostics,
			IsInputTerminal: func() bool { return true },
		})
		root.SetArgs(args)
		err := root.ExecuteContext(t.Context())
		require.ErrorContains(t, err, "prompts are disabled")
		require.Empty(t, out.String())
		require.NotContains(t, diagnostics.String(), "Email:")
		require.NotContains(t, diagnostics.String(), "Verification code:")
		require.NotContains(t, diagnostics.String(), "Revoke API key")
	}
}

func TestExplicitPromptFlagOverridesEnvironment(t *testing.T) {
	t.Setenv("SCOPEDB_PROMPT_DISABLED", "1")
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In: strings.NewReader("n\n"), Out: &out, ErrOut: &diagnostics,
		IsInputTerminal: func() bool { return true },
	})
	root.SetArgs([]string{"api-key", "revoke", "automation", "--no-prompt=false"})
	require.NoError(t, root.ExecuteContext(t.Context()))
	require.Equal(t, "Cancelled.\n", out.String())
	require.Contains(t, diagnostics.String(), "Revoke API key")
}

func TestRevokeWorkspaceOverridePromptNamesTarget(t *testing.T) {
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In: strings.NewReader("n\n"), Out: &out, ErrOut: &diagnostics,
		IsInputTerminal: func() bool { return true },
	})
	root.SetArgs([]string{"api-key", "revoke", "automation", "--workspace", "Beta"})
	require.NoError(t, root.ExecuteContext(t.Context()))
	require.Equal(t, "Cancelled.\n", out.String())
	require.Contains(t, diagnostics.String(), "Revoke API key automation in workspace Beta?")
}

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
