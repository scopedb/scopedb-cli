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
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/stretchr/testify/require"
)

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
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Shared")}
	fake.APIKeys = []controlplane.APIKey{{ID: "key-1", Name: "automation", Status: "active"}}
	fake.RefreshedAccessToken = "oat_rotated"
	started := time.Now().UTC()
	now := started
	saveLogin(t, store, fake.URL, "ws-1", started.Add(2*time.Minute), started.Add(24*time.Hour))
	var deleteToken, deletePath string
	out, _, err := runCommandWith(t, Dependencies{
		In: confirmationReader{Reader: strings.NewReader("y\n"), beforeRead: func() error {
			now = started.Add(5 * time.Minute)
			// A concurrent workspace selection must not redirect the confirmed deletion.
			state, err := store.Load(fake.URL)
			if err != nil {
				return err
			}
			state.WorkspaceID = "ws-2"
			return store.Save(fake.URL, state)
		}},
		IsInputTerminal: func() bool { return true },
		Now:             func() time.Time { return now },
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodDelete {
				deleteToken, deletePath = r.Header.Get("Authorization"), r.URL.Path
			}
			return http.DefaultTransport.RoundTrip(r)
		})},
	}, "--control-url", fake.URL, "api-key", "revoke", "key-1", "--format", "json")
	require.NoError(t, err)
	require.Equal(t, 1, fake.Refreshes)
	require.Equal(t, "Bearer "+fake.RefreshedAccessToken, deleteToken)
	require.Equal(t, "/api/workspaces/ws-1/api-keys/key-1", deletePath)
	require.JSONEq(t, `{"id":"key-1","name":"automation","revoked":true}`, out)
}

func TestAPIKeyRevokeStopsOnHTTPFailure(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Shared")}
			fake.APIKeys = []controlplane.APIKey{{ID: "key-1", Name: "automation"}}
			saveStoredLogin(t, store, fake.URL, "ws-1")
			out, _, err := runCommandWith(t, Dependencies{
				HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.Method == method && strings.Contains(r.URL.Path, "/api-keys") {
						return nil, io.ErrUnexpectedEOF
					}
					return http.DefaultTransport.RoundTrip(r)
				})},
			}, "--control-url", fake.URL, "api-key", "revoke", "key-1", "--yes", "--format", "json")
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
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
		require.Regexp(t, regexp.QuoteMeta(key.ID)+`[^\n]*`+regexp.QuoteMeta(key.CreatedBy), out)
		require.NotContains(t, out+diagnostics, key.Key)
	}
}

func TestAPIKeyCreateRequiresExpiration(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Shared")}
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, _, err := runCommand(t, "--control-url", fake.URL, "api-key", "create", "automation")
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	rendered := clierror.Render(err)
	require.Contains(t, rendered, "--expires-in")
	require.Contains(t, rendered, "--expires-at")
	require.Empty(t, out)
	require.Empty(t, fake.APIKeyRequests)
}

func TestAPIKeyCreateSendsRequestedExpiration(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		name    string
		flags   []string
		expires time.Time
	}{
		{name: "relative", flags: []string{"--expires-in", "720h"}, expires: now.Add(720 * time.Hour)},
		{name: "absolute", flags: []string{"--expires-at", now.Add(720 * time.Hour).Format(time.RFC3339)}, expires: now.Add(720 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Shared")}
			saveStoredLogin(t, store, fake.URL, "ws-1")

			args := append([]string{"--control-url", fake.URL, "api-key", "create", "automation"}, tc.flags...)
			out, _, err := runCommandWith(t, Dependencies{
				Now: func() time.Time { return now },
			}, args...)
			require.NoError(t, err)
			require.Equal(t, "secret-key\n", out)
			require.Len(t, fake.APIKeyRequests, 1)
			require.Equal(t, tc.expires, fake.APIKeyRequests[0].ExpiresAt)
		})
	}
}

func TestAPIKeyRevokeResolvesIDOrUniqueName(t *testing.T) {
	fullKey := "sk_" + strings.Repeat("a", 16) + strings.Repeat("b", 48)
	for _, tc := range []struct {
		name        string
		input       string
		wantID      string
		wantName    string
		wantCode    int
		wantMessage string
	}{
		{name: "id takes precedence over a matching name", input: "key-4", wantID: "key-4", wantName: "duplicate"},
		{name: "unique name", input: "ci", wantID: "key-2", wantName: "ci"},
		{name: "ambiguous name", input: "duplicate", wantCode: clierror.ExitUsage, wantMessage: "ambiguous"},
		{name: "full secret is not an ID", input: fullKey, wantCode: clierror.ExitNotFound, wantMessage: "scope api-key list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
			fake.APIKeys = []controlplane.APIKey{
				{ID: "key-2", Name: "ci", Status: "active"},
				{ID: "key-3", Name: "duplicate", Status: "active"},
				{ID: "key-4", Name: "duplicate", Status: "active"},
				{ID: "key-5", Name: "key-4", Status: "active"},
			}
			saveStoredLogin(t, store, fake.URL, "ws-1")

			out, diagnostics, err := runCommand(t, "--control-url", fake.URL, "api-key", "revoke", tc.input, "--yes")
			if tc.wantCode != 0 {
				require.Equal(t, tc.wantCode, clierror.ExitCode(err))
				require.Contains(t, clierror.Render(err), tc.wantMessage)
				require.NotContains(t, out+diagnostics+clierror.Render(err), tc.input)
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
