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
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/require"
)

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestCommandsReportTableWriteFailures(t *testing.T) {
	for _, args := range []string{"workspace list", "workspace get", "api-key list", "auth status", "doctor"} {
		t.Run(args, func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
			fake.Details["ws-1"] = controlplane.WorkspaceDetails{Workspace: fake.Workspaces[0]}
			fake.APIKeys = []controlplane.APIKey{{ID: "key-1", Name: "automation", Status: "active"}}
			if args == "doctor" {
				fake.User.Status = "pending"
			}
			saveStoredLogin(t, store, fake.URL, "ws-1")
			writeErr := errors.New("output is full")
			root := NewRoot(Dependencies{
				Out: failingWriter{writeErr}, ErrOut: io.Discard, Getenv: func(string) string { return "" },
			})
			root.SetArgs(append([]string{"--control-url", fake.URL}, strings.Fields(args)...))
			require.ErrorIs(t, root.ExecuteContext(t.Context()), writeErr)
		})
	}
}

func TestCommandJSONOutput(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha"), workspaceFixture("ws-2", "Beta")}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	for _, step := range []struct {
		args string
		json string
	}{
		{"workspace list --limit 1", `[{"id":"ws-1","display_name":"Alpha","status":"ready","current":true}]`},
		{"workspace use Beta", `{"id":"ws-2","display_name":"Beta","changed":true}`},
		{"workspace use ws-2", `{"id":"ws-2","display_name":"Beta","changed":false}`},
		{"api-key revoke automation --yes", `{"name":"automation","revoked":true}`},
		{"auth logout", `{"changed":true}`},
	} {
		args := append([]string{"--control-url", fake.URL}, strings.Fields(step.args)...)
		args = append(args, "--format", "json")
		out, diagnostics, err := runCommand(t, args...)
		require.NoError(t, err, step.args)
		require.Empty(t, diagnostics, step.args)
		require.JSONEq(t, step.json, out, step.args)
	}
	require.Equal(t, []string{"automation"}, fake.RevokedAPIKeys)
	_, err := store.Load(fake.URL)
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

func TestWorkspaceUseTextOutput(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, diagnostics, err := runCommand(t, "--control-url", fake.URL, "workspace", "use", "Alpha")
	require.NoError(t, err)
	require.Empty(t, diagnostics)
	require.Contains(t, out, "Already using workspace Alpha (ws-1) for this login.")
}

func TestWorkspaceUseRejectsScheduledWorkspace(t *testing.T) {
	fake, store := setupCLITest(t)
	scheduled := workspaceFixture("ws-9", "Retiring")
	scheduledAt := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	scheduled.ScheduledForDeletionAt = &scheduledAt
	fake.Workspaces = []controlplane.Workspace{scheduled}
	saveStoredLogin(t, store, fake.URL, "")

	_, _, err := runCommand(t, "--control-url", fake.URL, "workspace", "use", "ws-9")
	require.ErrorContains(t, err, "scheduled for deletion")
	state, loadErr := store.Load(fake.URL)
	require.NoError(t, loadErr)
	require.Empty(t, state.WorkspaceID)
}

func TestWorkspaceUseWarnsAboutEnvironmentCredentials(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	saveStoredLogin(t, store, fake.URL, "")

	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		Out: &out, ErrOut: &diagnostics,
		Sleep: func(time.Duration) {},
		Getenv: func(name string) string {
			switch name {
			case "SCOPEDB_ENDPOINT":
				return "https://data.example.com"
			case "SCOPEDB_API_KEY":
				return "machine-secret"
			}
			return ""
		},
	})
	root.SetArgs([]string{"--control-url", fake.URL, "workspace", "use", "Alpha"})
	require.NoError(t, root.ExecuteContext(t.Context()))
	require.Contains(t, diagnostics.String(), "SCOPEDB_ENDPOINT and SCOPEDB_API_KEY")
	require.NotContains(t, diagnostics.String(), "machine-secret")
}

func TestConsoleOutput(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_CONSOLE_URL", "https://console.example.com")
	for _, tc := range []struct {
		args   string
		output string
		opened string
	}{
		{"console", "https://console.example.com/home\n", ""},
		{"console query --open", "https://console.example.com/query\n", "https://console.example.com/query"},
		{"console query --format json", `{"page":"query","url":"https://console.example.com/query","opened":false}`, ""},
		{"console query --open --format json", `{"page":"query","url":"https://console.example.com/query","opened":true}`, "https://console.example.com/query"},
	} {
		t.Run(tc.args, func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			var opened string
			root := NewRoot(Dependencies{Out: &out, ErrOut: &diagnostics, OpenURL: func(url string) error {
				opened = url
				return nil
			}})
			root.SetArgs(strings.Fields(tc.args))
			require.NoError(t, root.ExecuteContext(t.Context()))
			if strings.Contains(tc.args, "--format json") {
				require.JSONEq(t, tc.output, out.String())
			} else {
				require.Equal(t, tc.output, out.String())
			}
			require.Empty(t, diagnostics.String())
			require.Equal(t, tc.opened, opened)
		})
	}
}

func TestVersionJSONAlias(t *testing.T) {
	legacy, _, err := runCommand(t, "version", "--json")
	require.NoError(t, err)
	out, _, err := runCommand(t, "version", "--format", "json")
	require.NoError(t, err)
	require.JSONEq(t, legacy, out)
}
