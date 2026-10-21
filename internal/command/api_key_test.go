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
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyListUsesTheSelectedWorkspace(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	fake.APIKeys = []controlplane.APIKey{{
		ID: "key-1", Name: "automation", Tags: []string{"env=ci"}, Status: "active",
		CreatedBy: "dev@example.com", CreatedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		Key: "should-not-appear",
	}}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, _, err := runCommand(t, "--control-url", fake.URL, "api-key", "list", "--format", "json")
	require.NoError(t, err)
	var items []apiKeyListItem
	require.NoError(t, json.Unmarshal([]byte(out), &items))
	require.Len(t, items, 1)
	require.Equal(t, "key-1", items[0].ID)
	require.Equal(t, "automation", items[0].Name)
	require.Equal(t, []string{"env=ci"}, items[0].Tags)
	require.NotContains(t, out, "should-not-appear")
}

func TestAPIKeyListHonorsTheLimit(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	fake.APIKeys = []controlplane.APIKey{
		{ID: "key-1", Name: "one", Status: "active"},
		{ID: "key-2", Name: "two", Status: "active"},
	}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, _, err := runCommand(t, "--control-url", fake.URL, "api-key", "list", "--format", "json", "--limit", "1")
	require.NoError(t, err)
	var items []apiKeyListItem
	require.NoError(t, json.Unmarshal([]byte(out), &items))
	require.Len(t, items, 1)
	require.Equal(t, "key-1", items[0].ID)
}

func TestAPIKeyCreatePrintsTheSecretOnce(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, diagnostics, err := runCommand(t, "--control-url", fake.URL, "api-key", "create", "automation", "--tag", "env=ci", "--expires-in", "12h")
	require.NoError(t, err)
	require.Equal(t, "secret-key\n", out)
	require.Contains(t, diagnostics, "Created API key automation. This secret is shown only once.")
	require.Len(t, fake.APIKeyRequests, 1)
	require.Equal(t, "automation", fake.APIKeyRequests[0].Name)
	require.Equal(t, []string{"env=ci"}, fake.APIKeyRequests[0].Tags)
	require.NotNil(t, fake.APIKeyRequests[0].ExpiresAt)
	require.True(t, fake.APIKeyRequests[0].ExpiresAt.After(time.Now()))
}

func TestAPIKeyRevokeRequiresYesWhenNotInteractive(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	_, _, err := runCommand(t, "--control-url", fake.URL, "api-key", "revoke", "automation")
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "--yes is required")
	require.Empty(t, fake.RevokedAPIKeys)
}

func TestAPIKeyRevokeReportsJSON(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, _, err := runCommand(t, "--control-url", fake.URL, "api-key", "revoke", "automation", "--yes", "--format", "json")
	require.NoError(t, err)
	require.JSONEq(t, `{"name":"automation","revoked":true}`, out)
	require.Equal(t, []string{"automation"}, fake.RevokedAPIKeys)
}

func TestAPIKeyCommandsRequireASelectedWorkspace(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	saveStoredLogin(t, store, fake.URL, "")

	_, _, err := runCommand(t, "--control-url", fake.URL, "api-key", "list")
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "no workspace is selected")
}
