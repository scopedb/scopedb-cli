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
	"strings"
	"testing"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyListIdentifiesDuplicateNamesByCreator(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Shared")}
	fake.APIKeys = []controlplane.APIKey{
		{ID: "key-1", Name: "automation", CreatedBy: "alice@example.com", Key: "alice-key-secret"},
		{ID: "key-2", Name: "automation", CreatedBy: "bob@example.com", Key: "bob-key-secret"},
	}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, diagnostics, err := runCommand(t, "--control-url", fake.URL, "api-key", "list")
	require.NoError(t, err)
	require.Empty(t, diagnostics)
	for _, key := range fake.APIKeys {
		var row string
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, key.ID) {
				row = line
				break
			}
		}
		require.NotEmpty(t, row, "missing API key %s", key.ID)
		require.Contains(t, row, key.Name)
		require.Contains(t, row, key.CreatedBy)
		require.NotContains(t, out+diagnostics, key.Key)
	}
}

func TestAPIKeyRevokeResolvesIDOrUniqueName(t *testing.T) {
	for _, tc := range []struct {
		name        string
		input       string
		wantID      string
		wantName    string
		wantCode    int
		wantMessage string
	}{
		{name: "id", input: "key-2", wantID: "key-2", wantName: "ci"},
		{name: "id selects one duplicate", input: "key-3", wantID: "key-3", wantName: "duplicate"},
		{name: "id takes precedence over a matching name", input: "key-4", wantID: "key-4", wantName: "duplicate"},
		{name: "unique name", input: "ci", wantID: "key-2", wantName: "ci"},
		{name: "padded name", input: " ci ", wantID: "key-2", wantName: "ci"},
		{name: "ambiguous name", input: "duplicate", wantCode: clierror.ExitUsage, wantMessage: "ambiguous"},
		{name: "missing", input: "missing", wantCode: clierror.ExitNotFound, wantMessage: "was not found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
			fake.APIKeys = []controlplane.APIKey{
				{ID: "key-1", Name: "automation", Status: "active"},
				{ID: "key-2", Name: "ci", Status: "active"},
				{ID: "key-3", Name: "duplicate", Status: "active"},
				{ID: "key-4", Name: "duplicate", Status: "active"},
				{ID: "key-5", Name: "key-4", Status: "active"},
			}
			saveStoredLogin(t, store, fake.URL, "ws-1")

			out, _, err := runCommand(t, "--control-url", fake.URL, "api-key", "revoke", tc.input, "--yes")
			if tc.wantCode != 0 {
				require.Equal(t, tc.wantCode, clierror.ExitCode(err))
				require.Contains(t, clierror.Render(err), tc.wantMessage)
				require.Empty(t, fake.RevokedAPIKeys)
				return
			}
			require.NoError(t, err)
			require.Equal(t, []string{tc.wantID}, fake.RevokedAPIKeys)
			require.Contains(t, out, tc.wantName)
			require.Contains(t, out, tc.wantID)
		})
	}
}
