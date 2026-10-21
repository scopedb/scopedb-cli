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

	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/stretchr/testify/require"
)

func TestListWithoutSelectedWorkspaceShowsEveryWorkspace(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha"), workspaceFixture("ws-2", "Beta")}
	saveStoredLogin(t, store, fake.URL, "")

	out, diagnostics, err := runCommand(t, "--control-url", fake.URL, "workspace", "list", "--format", "json")
	require.NoError(t, err)
	require.Empty(t, diagnostics)
	var items []workspaceListItem
	require.NoError(t, json.Unmarshal([]byte(out), &items))
	require.Equal(t, []workspaceListItem{
		{ID: "ws-1", DisplayName: new("Alpha"), Status: "ready"},
		{ID: "ws-2", DisplayName: new("Beta"), Status: "ready"},
	}, items)

	out, diagnostics, err = runCommand(t, "--control-url", fake.URL, "workspace", "list")
	require.NoError(t, err)
	require.Empty(t, diagnostics)
	for _, workspace := range items {
		require.Contains(t, out, workspace.ID)
		require.Contains(t, out, *workspace.DisplayName)
	}
}

func TestListMarksLifecycleState(t *testing.T) {
	fake, store := setupCLITest(t)
	provisioning := workspaceFixture("ws-2", "Starting")
	provisioning.ProvisioningStatus = "provisioning"
	scheduled := workspaceFixture("ws-3", "Retiring")
	scheduledAt := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	scheduled.ScheduledForDeletionAt = &scheduledAt
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Ready"), provisioning, scheduled}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, _, err := runCommand(t, "--control-url", fake.URL, "workspace", "list", "--format", "json", "--limit", "3")
	require.NoError(t, err)
	var items []workspaceListItem
	require.NoError(t, json.Unmarshal([]byte(out), &items))
	require.Equal(t, []string{"ready", "provisioning", "scheduled for deletion"}, []string{items[0].Status, items[1].Status, items[2].Status})
	require.True(t, items[0].Current)
}

func TestListLimitAndEmptyAccount(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{
		workspaceFixture("ws-1", "Alpha"), workspaceFixture("ws-2", "Beta"), workspaceFixture("ws-3", "Gamma"),
	}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, _, err := runCommand(t, "--control-url", fake.URL, "workspace", "list", "--format", "json", "--limit", "2")
	require.NoError(t, err)
	var items []map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &items))
	require.Len(t, items, 2)

	out, _, err = runCommand(t, "--control-url", fake.URL, "workspace", "list", "--format", "json", "--limit", "0")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(out), &items))
	require.Len(t, items, 3)

	out, _, err = runCommand(t, "--control-url", fake.URL, "workspace", "list", "--limit", "-1")
	require.ErrorContains(t, err, "--limit must not be negative")
	require.Empty(t, out)
}

func TestListGuidesAccountWithoutWorkspaces(t *testing.T) {
	fake, store := setupCLITest(t)
	saveStoredLogin(t, store, fake.URL, "")

	out, diagnostics, err := runCommand(t, "--control-url", fake.URL, "workspace", "list", "--format", "json")
	require.NoError(t, err)
	require.JSONEq(t, `[]`, out)
	require.Contains(t, diagnostics, "no workspaces")
	require.Contains(t, diagnostics, "scope workspace create")
}

func TestWorkspaceGetRequiresSelection(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	saveStoredLogin(t, store, fake.URL, "")

	out, _, err := runCommand(t, "--control-url", fake.URL, "workspace", "get")
	require.ErrorContains(t, err, "no workspace is selected")
	require.Empty(t, out)
}

func TestListLimitsCapRenderedItems(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha"), workspaceFixture("ws-2", "Beta"), workspaceFixture("ws-3", "Gamma")}
	fake.APIKeys = []controlplane.APIKey{
		{ID: "key-1", Name: "first", Status: "active", Key: "returned-key-secret"},
		{ID: "key-2", Name: "second", Status: "active"},
		{ID: "key-3", Name: "third", Status: "active"},
	}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	for _, args := range [][]string{
		{"workspace", "list", "--format", "json", "--limit", "2"},
		{"api-key", "list", "--format", "json", "--limit", "2"},
	} {
		out, _, err := runCommand(t, append([]string{"--control-url", fake.URL}, args...)...)
		require.NoError(t, err)
		require.NotContains(t, out, "returned-key-secret")
		var items []map[string]any
		require.NoError(t, json.Unmarshal([]byte(out), &items))
		require.Len(t, items, 2)
	}

	out, _, err := runCommand(t, "--control-url", fake.URL, "api-key", "list", "--limit", "1")
	require.NoError(t, err)
	require.Contains(t, out, "first")
	require.NotContains(t, out, "second")

	out, _, err = runCommand(t, "--control-url", fake.URL, "workspace", "list", "--format", "json", "--limit", "0")
	require.NoError(t, err)
	var items []map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &items))
	require.Len(t, items, 3)

	out, _, err = runCommand(t, "--control-url", fake.URL, "api-key", "list", "--limit", "-1")
	require.ErrorContains(t, err, "--limit must not be negative")
	require.Empty(t, out)
}
