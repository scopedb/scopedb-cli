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
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceUseRequiresAnAccessibleWorkspaceID(t *testing.T) {
	for _, value := range []string{"missing", "Beta", "beta"} {
		t.Run(value, func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha"), workspaceFixture("ws-2", "Beta")}
			saveStoredLogin(t, store, fake.URL, "ws-1")

			out, _, err := runCommand(t, "workspace", "use", value)
			require.Equal(t, clierror.ExitNotFound, clierror.ExitCode(err))
			require.Contains(t, clierror.Render(err), "scope workspace list")
			require.Empty(t, out)
			state, err := store.Load(fake.URL)
			require.NoError(t, err)
			require.Equal(t, "ws-1", state.WorkspaceID)
		})
	}
}

func TestWorkspaceGetShowsSelectedWorkspace(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	fake.Details["ws-1"] = controlplane.WorkspaceDetails{
		Workspace:    controlplane.Workspace{ID: "ws-1"},
		Connection:   controlplane.Connection{APIBaseURL: "https://data.example.com", AuthScheme: "Bearer"},
		Placement:    controlplane.Placement{Provider: "aws", Region: "us-east-1"},
		Provisioning: controlplane.Provisioning{Status: "ready"},
	}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, _, err := runCommand(t, "--control-url", fake.URL, "workspace", "get", "--format", "json")
	require.NoError(t, err)
	var view workspaceView
	require.NoError(t, json.Unmarshal([]byte(out), &view))
	require.Equal(t, "ws-1", view.Workspace.ID)
	require.Equal(t, "https://data.example.com", view.Connection.Endpoint)
	require.Equal(t, "ready", view.Provisioning.Status)
}

func TestCommandsKeepTheirLoginSnapshot(t *testing.T) {
	for _, args := range [][]string{{"workspace", "get"}, {"auth", "status"}} {
		t.Run(args[0], func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
			fake.Details["ws-1"] = controlplane.WorkspaceDetails{Workspace: fake.Workspaces[0]}
			var detailToken string
			saveStoredLogin(t, store, fake.URL, "ws-1")

			commandArgs := append([]string{"--control-url", fake.URL}, args...)
			commandArgs = append(commandArgs, "--format", "json")
			out, _, err := runCommandWith(t, Dependencies{
				HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/api/workspaces" {
						// Replace the saved login while the command is reading its original account.
						if err := store.Save(fake.URL, credential.State{
							AccessToken: "another-login", AccessTokenExpiresAt: time.Now().Add(time.Hour),
							RefreshToken: "another-refresh", WorkspaceID: "ws-2",
						}); err != nil {
							return nil, err
						}
					}
					if r.URL.Path == "/api/workspaces/ws-1" {
						detailToken = r.Header.Get("Authorization")
					}
					return http.DefaultTransport.RoundTrip(r)
				})},
			}, commandArgs...)
			require.NoError(t, err)
			if args[0] == "workspace" {
				var view workspaceView
				require.NoError(t, json.Unmarshal([]byte(out), &view))
				require.Equal(t, "ws-1", view.Workspace.ID)
			} else {
				var view statusView
				require.NoError(t, json.Unmarshal([]byte(out), &view))
				require.Equal(t, "ws-1", view.WorkspaceID)
				require.Equal(t, fake.User.Email, view.Email)
				require.NotEmpty(t, view.RefreshTokenExpiresAt)
			}
			require.Equal(t, "Bearer "+fake.AccessToken, detailToken)
			state, err := store.Load(fake.URL)
			require.NoError(t, err)
			require.Equal(t, "ws-2", state.WorkspaceID)
		})
	}
}

func TestStatusReportsOAuthLogin(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	fake.Details["ws-1"] = controlplane.WorkspaceDetails{
		Workspace:    controlplane.Workspace{ID: "ws-1"},
		Connection:   controlplane.Connection{APIBaseURL: "https://data.example.com"},
		Provisioning: controlplane.Provisioning{Status: "ready"},
	}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, diagnostics, err := runCommand(t, "--control-url", fake.URL, "auth", "status", "--format", "json")
	require.NoError(t, err)
	require.Empty(t, diagnostics)
	var view statusView
	require.NoError(t, json.Unmarshal([]byte(out), &view))
	require.Equal(t, "dev@example.com", view.Email)
	require.Equal(t, "ws-1", view.WorkspaceID)
	require.Equal(t, "https://data.example.com", view.Endpoint)
	require.NotEmpty(t, view.RefreshTokenExpiresAt)
}

func TestStatusClearsUnavailableWorkspace(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-2", "Beta")}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, diagnostics, err := runCommand(t, "--control-url", fake.URL, "auth", "status", "--format", "json")
	require.NoError(t, err)
	var view statusView
	require.NoError(t, json.Unmarshal([]byte(out), &view))
	require.Empty(t, view.WorkspaceID)
	require.Contains(t, diagnostics, "no longer available")
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Empty(t, state.WorkspaceID)
}

func TestStatusGuidesPendingAccount(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.User.Status = "pending"
	saveStoredLogin(t, store, fake.URL, "")

	_, diagnostics, err := runCommand(t, "--control-url", fake.URL, "auth", "status", "--format", "json")
	require.NoError(t, err)
	require.Contains(t, diagnostics, "awaiting approval")
	require.Contains(t, diagnostics, "scope console --open")
}

func TestStatusWithoutLogin(t *testing.T) {
	fake, _ := setupCLITest(t)
	out, _, err := runCommand(t, "--control-url", fake.URL, "auth", "status", "--format", "json")
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(err))
	require.Empty(t, out)
	require.Contains(t, clierror.Render(err), "scope auth login")
}

func TestLoginWorkspaceIgnoresEnvironmentCredentials(t *testing.T) {
	fake, _ := setupDataPlaneLogin(t, "https://workspace.example.com")
	t.Setenv("SCOPEDB_ENDPOINT", "https://data.example.com")
	t.Setenv("SCOPEDB_API_KEY", "machine-secret")

	out, _, err := runCommand(t, "auth", "status", "--format", "json")
	require.NoError(t, err)
	var view statusView
	require.NoError(t, json.Unmarshal([]byte(out), &view))
	require.Equal(t, credential.SourcePlaintext, view.CredentialSource)
	require.Equal(t, "ws-1", view.WorkspaceID)
	require.Equal(t, "https://workspace.example.com", view.Endpoint)

	queries := 0
	out, _, err = runCommandWith(t, Dependencies{HTTPClient: fake.dataClient(func(r *http.Request) (*http.Response, error) {
		queries++
		require.Equal(t, "https://workspace.example.com/v1/statements", r.URL.String())
		require.NotContains(t, r.Header.Get("Authorization"), "machine-secret")
		return finishedQueryResponse(r), nil
	})}, "query", "SELECT 1 AS ready", "--format", "json")
	require.NoError(t, err)
	require.Equal(t, 1, queries)
	require.JSONEq(t, `[{"ready":1}]`, out)
}
