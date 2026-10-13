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
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceCreateUsesDefaultPlacement(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Signup = controlplane.SignupConfig{DefaultPlacement: &controlplane.Placement{Provider: "aws", Region: "eu-west-1"}}
	saveStoredLogin(t, store, fake.URL, "")

	out, diagnostics, err := runCommand(t, "--control-url", fake.URL, "workspace", "create", "--name", "Analytics", "--format", "json")
	require.NoError(t, err)
	require.Empty(t, diagnostics)
	require.JSONEq(t, `{"id":"ws-new","provider":"aws","region":"eu-west-1"}`, out)
}

func TestWorkspaceCreateRequiresChoiceWithoutDefault(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Signup = controlplane.SignupConfig{Placements: []controlplane.Placement{
		{Provider: "aws", Region: "us-east-1"}, {Provider: "aws", Region: "eu-west-1"},
	}}
	saveStoredLogin(t, store, fake.URL, "")

	out, _, err := runCommand(t, "--control-url", fake.URL, "workspace", "create")
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "aws/us-east-1, aws/eu-west-1")
	require.Empty(t, out)
}

func TestWorkspaceCreateAcceptsExplicitPlacement(t *testing.T) {
	fake, store := setupCLITest(t)
	saveStoredLogin(t, store, fake.URL, "")

	out, _, err := runCommand(t, "--control-url", fake.URL, "workspace", "create", "--provider", "aws", "--region", "ap-northeast-1")
	require.NoError(t, err)
	require.Contains(t, out, "Created workspace ws-new.")
	require.Contains(t, out, "scope workspace use ws-new")
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
	require.Equal(t, "oauth", view.AuthMode)
	require.Equal(t, "dev@example.com", view.Email)
	require.Equal(t, "ws-1", view.WorkspaceID)
	require.Equal(t, "https://data.example.com", view.Endpoint)
	require.NotEmpty(t, view.LoginExpiresAt)
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

func TestStatusMachineCredentialsSkipTheLogin(t *testing.T) {
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
	root.SetArgs([]string{"auth", "status", "--format", "json"})
	require.NoError(t, root.ExecuteContext(t.Context()))
	require.JSONEq(t, `{"auth_mode":"api_key","credential_source":"environment","endpoint":"https://data.example.com"}`, out.String())
	require.NotContains(t, out.String()+diagnostics.String(), "machine-secret")
}

func TestStatusRefreshesExpiredLogin(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	fake.Details["ws-1"] = controlplane.WorkspaceDetails{
		Workspace:    controlplane.Workspace{ID: "ws-1"},
		Provisioning: controlplane.Provisioning{Status: "ready"},
	}
	state := saveStoredLogin(t, store, fake.URL, "ws-1")
	state.AccessTokenExpiresAt = time.Now().Add(-time.Hour)
	require.NoError(t, store.Save(fake.URL, state))

	_, _, err := runCommand(t, "--control-url", fake.URL, "auth", "status", "--format", "json")
	require.NoError(t, err, "an expired access token refreshes before the account lookup")
	require.Equal(t, 1, fake.Refreshes)
}

func TestQueryWithoutLoginReportsLoginHint(t *testing.T) {
	fake, _ := setupCLITest(t)
	out, _, err := runCommand(t, "--control-url", fake.URL, "query", "SELECT 1 AS ready")
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(NormalizeError(err)))
	require.Empty(t, out)
	require.Contains(t, clierror.Render(NormalizeError(err)), "scope auth login")
}

func TestUnreachableControlPlaneIsTemporary(t *testing.T) {
	fake, store := setupCLITest(t)
	saveStoredLogin(t, store, fake.URL, "")
	fake.CreateWorkspaceStatus = http.StatusInternalServerError

	_, _, err := runCommand(t, "--control-url", fake.URL, "workspace", "create", "--provider", "aws", "--region", "us-east-1")
	require.Equal(t, clierror.ExitTemporary, clierror.ExitCode(NormalizeError(err)))
}
