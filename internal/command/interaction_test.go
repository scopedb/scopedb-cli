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

	"github.com/scopedb/scopedb-cli/internal/clierror"
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
	t.Setenv("SCOPEDB_NO_INTERACTIVE", "true")
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

func TestInteractionFlagAndEnvironmentPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		env    string
		flag   string
		errMsg string
	}{
		{name: "default"},
		{name: "environment false", env: "false"},
		{name: "environment zero", env: "0"},
		{name: "environment true", env: "true", errMsg: "--yes is required when prompts are disabled"},
		{name: "environment one", env: "1", errMsg: "--yes is required when prompts are disabled"},
		{name: "invalid environment", env: "invalid-secret", errMsg: "SCOPEDB_NO_INTERACTIVE must be a boolean"},
		{name: "flag enables prompts", env: "true", flag: "--no-interactive=false"},
		{name: "flag disables prompts", env: "false", flag: "--no-interactive", errMsg: "--yes is required when prompts are disabled"},
		{name: "flag overrides invalid environment", env: "invalid-secret", flag: "--no-interactive=false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SCOPEDB_NO_INTERACTIVE", tc.env)
			var out, diagnostics bytes.Buffer
			root := NewRoot(Dependencies{
				In: strings.NewReader("n\n"), Out: &out, ErrOut: &diagnostics,
				IsInputTerminal: func() bool { return true },
			})
			args := []string{"api-key", "revoke", "automation"}
			if tc.flag != "" {
				args = append(args, tc.flag)
			}
			root.SetArgs(args)
			err := root.ExecuteContext(t.Context())
			if tc.errMsg != "" {
				require.ErrorContains(t, err, tc.errMsg)
				require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
				require.NotContains(t, err.Error(), "invalid-secret")
				require.Empty(t, out.String())
				require.Empty(t, diagnostics.String())
				return
			}
			require.NoError(t, err)
			require.Equal(t, "Cancelled.\n", out.String())
			require.Contains(t, diagnostics.String(), "Revoke API key")
		})
	}
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
