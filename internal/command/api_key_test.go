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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyRevokeDoesNotEchoFullKey(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Shared")}
	saveStoredLogin(t, store, fake.URL, "ws-1")
	fullKey := "sk_" + strings.Repeat("a", 16) + strings.Repeat("b", 48)
	out, diagnostics, err := runCommand(t, "--control-url", fake.URL, "api-key", "revoke", fullKey, "--yes")
	require.Equal(t, clierror.ExitNotFound, clierror.ExitCode(err))
	require.NotContains(t, out+diagnostics+clierror.Render(err), fullKey)
	require.Contains(t, clierror.Render(err), "scope api-key list")
	require.Empty(t, fake.RevokedAPIKeys)
}

type confirmationReader struct {
	*strings.Reader
	beforeRead func() error
}

func (r confirmationReader) Read(p []byte) (int, error) {
	if err := r.beforeRead(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

func TestAPIKeyRevokeRefreshesAfterConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, answer string
		confirmed    bool
	}{
		{name: "confirmed", answer: "y\n", confirmed: true},
		{name: "cancelled", answer: "n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Shared")}
			fake.APIKeys = []controlplane.APIKey{{ID: "key-1", Name: "automation", Status: "active"}}
			fake.RefreshedAccessToken = "oat_rotated"
			started := time.Now().UTC()
			now := started
			var deleteToken, deletePath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					deleteToken, deletePath = r.Header.Get("Authorization"), r.URL.Path
				}
				fake.serve(w, r)
			}))
			t.Cleanup(server.Close)
			fake.URL, fake.Issuer = server.URL, server.URL
			saveLogin(t, store, fake.URL, "ws-1", started.Add(2*time.Minute), started.Add(24*time.Hour))
			var out, diagnostics bytes.Buffer
			root := NewRoot(Dependencies{
				In: confirmationReader{Reader: strings.NewReader(tc.answer), beforeRead: func() error {
					now = started.Add(5 * time.Minute)
					// A concurrent workspace selection must not redirect the confirmed deletion.
					state, err := store.Load(fake.URL)
					if err != nil {
						return err
					}
					state.WorkspaceID = "ws-2"
					return store.Save(fake.URL, state)
				}},
				Out: &out, ErrOut: &diagnostics,
				IsInputTerminal: func() bool { return true },
				Now:             func() time.Time { return now },
				Getenv:          func(string) string { return "" },
			})
			root.SetArgs([]string{"--control-url", fake.URL, "api-key", "revoke", "key-1", "--format", "json"})
			require.NoError(t, root.ExecuteContext(t.Context()))
			if tc.confirmed {
				require.Equal(t, 1, fake.Refreshes)
				require.Equal(t, "Bearer "+fake.RefreshedAccessToken, deleteToken)
				require.Equal(t, "/api/workspaces/ws-1/api-keys/key-1", deletePath)
				require.JSONEq(t, `{"id":"key-1","name":"automation","revoked":true}`, out.String())
			} else {
				require.Zero(t, fake.Refreshes)
				require.Empty(t, fake.RevokedAPIKeys)
				require.JSONEq(t, `{"id":"key-1","name":"automation","revoked":false}`, out.String())
			}
		})
	}
}

func TestAPIKeyRevokeReportsHTTPFailures(t *testing.T) {
	for _, tc := range []struct {
		method string
		status int
		code   int
	}{
		{http.MethodGet, http.StatusForbidden, clierror.ExitAuth},
		{http.MethodGet, http.StatusServiceUnavailable, clierror.ExitTemporary},
		{http.MethodDelete, http.StatusForbidden, clierror.ExitAuth},
		{http.MethodDelete, http.StatusNotFound, clierror.ExitNotFound},
		{http.MethodDelete, http.StatusServiceUnavailable, clierror.ExitTemporary},
	} {
		t.Run(tc.method+"/"+http.StatusText(tc.status), func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Shared")}
			fake.APIKeys = []controlplane.APIKey{{ID: "key-1", Name: "automation"}}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == tc.method && strings.Contains(r.URL.Path, "/api-keys") {
					w.WriteHeader(tc.status)
					return
				}
				fake.serve(w, r)
			}))
			t.Cleanup(server.Close)
			fake.URL = server.URL
			saveStoredLogin(t, store, fake.URL, "ws-1")
			out, _, err := runCommand(t, "--control-url", fake.URL, "api-key", "revoke", "key-1", "--yes", "--format", "json")
			require.Equal(t, tc.code, clierror.ExitCode(err))
			require.Empty(t, out)
			require.Empty(t, fake.RevokedAPIKeys)
		})
	}
}

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
