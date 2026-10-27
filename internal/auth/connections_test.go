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

package auth

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/require"
)

func connectionManager(t *testing.T, store CredentialStore, control ControlPlane, oauth OAuthClient, now time.Time) *Manager {
	t.Helper()
	manager := newManager(t, store, control, oauth, now)
	directory := t.TempDir()
	manager.Paths = config.Paths{Directory: directory, Config: filepath.Join(directory, "config.toml"), LockFile: filepath.Join(directory, "credentials.lock")}
	manager.LockFile = manager.Paths.LockFile
	manager.ConnectionName = "dev"
	manager.Connection = &config.Connection{ControlURL: manager.ControlURL, ConsoleURL: config.DefaultConsoleURL, WorkspaceID: "ws-1"}
	require.NoError(t, config.SaveConnection(manager.Paths, "dev", *manager.Connection, true))
	return manager
}

func TestConnectionCommandKeepsTargetWhileAnotherTerminalSelects(t *testing.T) {
	now := time.Now()
	state := loginState(now, now.Add(time.Hour))
	state.LoginID = "grant-one"
	store := &memoryStore{present: true, state: state}
	control := &fakeControl{user: controlplane.User{ID: "user-one", Status: "active"}, workspaces: []controlplane.Workspace{{ID: "ws-1"}, {ID: "ws-2"}}, details: controlplane.WorkspaceDetails{
		Connection: controlplane.Connection{APIBaseURL: "https://ws-1.example.com"}, Provisioning: controlplane.Provisioning{Status: "ready"},
	}}
	oauth := &fakeOAuth{results: []tokenOutcome{{tokens: accessTokens("rotated-access", "rotated-refresh")}}}
	manager := connectionManager(t, store, control, oauth, now)
	calls := 0
	control.exchangeToken = func(_ string, workspaceID string) (controlplane.TokenExchangeResponse, error) {
		require.Equal(t, "ws-1", workspaceID)
		calls++
		if calls == 1 {
			latest := *manager.Connection
			latest.WorkspaceID = "ws-2"
			require.NoError(t, config.SaveConnection(manager.Paths, "dev", latest, false))
			otherState := store.saved()
			otherState.WorkspaceID = "ws-2"
			require.NoError(t, store.Save(manager.ControlURL, otherState))
			return controlplane.TokenExchangeResponse{}, &controlplane.Error{Status: http.StatusUnauthorized}
		}
		return controlplane.TokenExchangeResponse{AccessToken: "data-token", TokenType: "Bearer", ExpiresAt: now.Add(time.Hour)}, nil
	}
	access, err := manager.ResolveDataAccess(t.Context())
	require.NoError(t, err)
	require.Equal(t, "ws-1", access.WorkspaceID)
	require.Equal(t, 2, calls)
	cfg, err := config.Read(manager.Paths)
	require.NoError(t, err)
	require.Equal(t, "ws-2", cfg.Connections["dev"].WorkspaceID)
	require.Equal(t, "ws-2", store.saved().WorkspaceID)
	// A stale status command clearing its old target must also preserve the new binding.
	require.NoError(t, manager.SelectWorkspace(t.Context(), ""))
	cfg, err = config.Read(manager.Paths)
	require.NoError(t, err)
	require.Equal(t, "ws-2", cfg.Connections["dev"].WorkspaceID)
}

func TestConnectionCommandDoesNotAdoptReplacementGrant(t *testing.T) {
	now := time.Now()
	state := loginState(now, now.Add(time.Hour))
	state.LoginID = "old-grant"
	store := &memoryStore{present: true, state: state}
	control := &fakeControl{user: controlplane.User{ID: "old-user", Status: "active"}, workspaces: []controlplane.Workspace{{ID: "ws-1"}}, details: controlplane.WorkspaceDetails{
		Connection: controlplane.Connection{APIBaseURL: "https://ws-1.example.com"}, Provisioning: controlplane.Provisioning{Status: "ready"},
	}}
	oauth := &fakeOAuth{}
	manager := connectionManager(t, store, control, oauth, now)
	control.exchangeToken = func(token, _ string) (controlplane.TokenExchangeResponse, error) {
		require.Equal(t, "oat_old", token)
		replacement := loginState(now, now.Add(time.Hour))
		replacement.LoginID = "new-grant"
		replacement.AccessToken = "another-account"
		require.NoError(t, store.Save(manager.ControlURL, replacement))
		return controlplane.TokenExchangeResponse{}, &controlplane.Error{Status: http.StatusUnauthorized}
	}
	_, err := manager.ResolveDataAccess(t.Context())
	require.ErrorIs(t, err, ErrLoginExpired)
	require.Zero(t, oauth.refreshCalls())
	require.Equal(t, "another-account", store.saved().AccessToken)
}

func TestConcurrentConnectionLoginsMergeConfigurationAndCredentialFile(t *testing.T) {
	now := time.Now()
	directory := t.TempDir()
	paths := config.Paths{Directory: directory, Config: filepath.Join(directory, "config.toml"), CredentialsFile: filepath.Join(directory, "credentials.json"), LockFile: filepath.Join(directory, "credentials.lock")}
	managers := make([]*Manager, 0, 2)
	for _, name := range []string{"dev", "prod"} {
		store := &credential.Stores{Keyring: &memoryStore{}, Plaintext: credential.NewPlaintextStore(paths.CredentialsFile, config.CredentialReference(paths, name)), InsecureStorage: true}
		manager := newManager(t, store, &fakeControl{}, &fakeOAuth{}, now)
		manager.ConnectionName = name
		manager.Connection = &config.Connection{ControlURL: manager.ControlURL, ConsoleURL: config.DefaultConsoleURL, WorkspaceID: "ws-" + name}
		manager.Paths, manager.LockFile = paths, paths.LockFile
		managers = append(managers, manager)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, manager := range managers {
		go func() {
			<-start
			results <- manager.SaveLogin(t.Context(), accessTokens("access-"+manager.ConnectionName, "refresh-"+manager.ConnectionName))
		}()
	}
	close(start)
	require.NoError(t, <-results)
	require.NoError(t, <-results)
	cfg, err := config.Read(paths)
	require.NoError(t, err)
	require.Len(t, cfg.Connections, 2)
	require.Contains(t, []string{"dev", "prod"}, cfg.DefaultConnection)
	for _, manager := range managers {
		state, err := manager.Credentials.Load(manager.ControlURL)
		require.NoError(t, err)
		require.Equal(t, "refresh-"+manager.ConnectionName, state.RefreshToken)
		require.Equal(t, "ws-"+manager.ConnectionName, cfg.Connections[manager.ConnectionName].WorkspaceID)
	}
}
