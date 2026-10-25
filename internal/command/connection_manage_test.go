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
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyConnectionLifecycle(t *testing.T) {
	for _, plaintext := range []bool{false, true} {
		t.Run(map[bool]string{false: "keyring", true: "plaintext"}[plaintext], func(t *testing.T) {
			fake, oauthStore := setupCLITest(t)
			saveStoredLogin(t, oauthStore, fake.URL, "ws-original")
			args := []string{"connection", "add", "job", "--auth-type", "api_key", "--endpoint", "https://job.example.com", "--api-key-stdin", "--format", "json"}
			if plaintext {
				args = append(args, "--insecure-storage")
			}
			secret := "job-key-secret"
			out, diagnostics, err := runCommandWith(t, Dependencies{In: strings.NewReader(secret + "\n")}, args...)
			require.NoError(t, err)
			require.NotContains(t, out+diagnostics, secret)
			paths, err := config.ResolvePaths()
			require.NoError(t, err)
			raw, err := os.ReadFile(paths.Config)
			require.NoError(t, err)
			require.NotContains(t, string(raw), secret)
			_, _, err = runCommand(t, "connection", "set-default", "job")
			require.NoError(t, err)
			out, _, err = runCommand(t, "auth", "status", "--format", "json")
			require.NoError(t, err)
			var view statusView
			require.NoError(t, json.Unmarshal([]byte(out), &view))
			require.Equal(t, "job", view.Connection)
			require.Equal(t, "api_key", view.AuthType)
			require.Equal(t, map[bool]string{false: "keyring", true: "plaintext"}[plaintext], view.CredentialSource)
			calls := 0
			deps := Dependencies{HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				require.Equal(t, "job.example.com", r.URL.Host)
				require.Equal(t, "Bearer "+secret, r.Header.Get("Authorization"))
				return finishedQueryResponse(r), nil
			})}}
			out, _, err = runCommandWith(t, deps, "query", "SELECT 1 AS ready", "--format", "json")
			require.NoError(t, err)
			require.JSONEq(t, `[{"ready":1}]`, out)
			require.Equal(t, 1, calls)
			for _, args := range [][]string{{"--workspace", "ws-other", "query", "SELECT 1"}, {"workspace", "list"}, {"auth", "login"}, {"auth", "logout"}} {
				_, _, err = runCommandWith(t, deps, args...)
				require.Error(t, err)
			}
			require.Equal(t, 1, calls)
			_, _, err = runCommand(t, "connection", "remove", "job")
			require.ErrorContains(t, err, "--yes")
			_, _, err = runCommandWith(t, Dependencies{In: strings.NewReader("n\n"), IsInputTerminal: func() bool { return true }}, "connection", "remove", "job")
			require.ErrorContains(t, err, "cancelled")
			_, _, err = runCommand(t, "connection", "remove", "job", "--yes")
			require.NoError(t, err)
			cfg, err := config.Read(paths)
			require.NoError(t, err)
			require.Empty(t, cfg.DefaultConnection)
			require.NotContains(t, cfg.Connections, "job")
			require.Contains(t, cfg.Connections, "default")
			_, _, err = runCommand(t, "auth", "status")
			require.ErrorIs(t, err, config.ErrUnknownConnection)
			stores := &credential.Stores{Keyring: credential.NewKeyringStore(config.CredentialReference(paths, "job")), Plaintext: credential.NewPlaintextStore(paths.CredentialsFile, config.CredentialReference(paths, "job"))}
			_, err = stores.Load("https://job.example.com")
			require.ErrorIs(t, err, credential.ErrNotFound)
			_, err = oauthStore.Load(fake.URL)
			require.NoError(t, err)
			require.Empty(t, fake.RevokedTokens)
			require.Empty(t, fake.RevokedAPIKeys)
		})
	}
}

func TestAPIKeyEnvironmentReferenceDoesNotFallBack(t *testing.T) {
	_, _ = setupCLITest(t)
	_, _, err := runCommand(t, "connection", "add", "job", "--auth-type", "api_key", "--endpoint", "https://job.example.com", "--api-key-env", "JOB_KEY")
	require.NoError(t, err)
	env := map[string]string{"SCOPEDB_CONNECTION": "job", "SCOPEDB_ENDPOINT": "https://wrong.example.com", "SCOPEDB_API_KEY": "wrong-key"}
	deps := Dependencies{Getenv: func(name string) string { return env[name] }}
	_, _, err = runCommandWith(t, deps, "auth", "status")
	require.ErrorContains(t, err, "no API key")
	env["JOB_KEY"] = "correct-key"
	out, _, err := runCommandWith(t, deps, "auth", "status", "--format", "json")
	require.NoError(t, err)
	require.Contains(t, out, "https://job.example.com")
	require.NotContains(t, out, "correct-key")
	require.NotContains(t, out, "wrong-key")
	_, _, err = runCommand(t, "connection", "add", "job", "--auth-type", "api_key", "--endpoint", "https://other.example.com", "--api-key-env", "OTHER_KEY")
	require.ErrorContains(t, err, "already exists")
}

func TestConnectionRemovalRetainsOAuthOnRevocationFailure(t *testing.T) {
	fake, store := setupCLITest(t)
	saveStoredLogin(t, store, fake.URL, "ws-original")
	fake.RevokedStatus = http.StatusServiceUnavailable
	_, _, err := runCommand(t, "connection", "remove", "default", "--yes")
	require.ErrorContains(t, err, "retained")
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	cfg, err := config.Read(paths)
	require.NoError(t, err)
	require.Equal(t, "default", cfg.DefaultConnection)
	_, err = store.Load(fake.URL)
	require.NoError(t, err)
	fake.RevokedStatus = 0
	_, _, err = runCommand(t, "connection", "remove", "default", "--yes")
	require.NoError(t, err)
	cfg, err = config.Read(paths)
	require.NoError(t, err)
	require.Empty(t, cfg.Connections)
	_, err = store.Load(fake.URL)
	require.ErrorIs(t, err, credential.ErrNotFound)
	require.Contains(t, fake.RevokedTokens, fake.RefreshToken)
}

func TestSingleCommandWorkspaceDoesNotChangeSavedSelection(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-one", "One"), workspaceFixture("ws-two", "Two")}
	for _, w := range fake.Workspaces {
		fake.Details[w.ID] = controlplane.WorkspaceDetails{Workspace: w, Connection: controlplane.Connection{APIBaseURL: "https://" + w.ID + ".example.com"}, Provisioning: controlplane.Provisioning{Status: "ready"}}
	}
	fake.Exchange = controlplane.TokenExchangeResponse{AccessToken: "data-token", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}
	saveStoredLogin(t, store, fake.URL, "ws-one")
	endpoints := []string{}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Host, ".example.com") {
			endpoints = append(endpoints, r.URL.Host)
			return finishedQueryResponse(r), nil
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	_, _, err := runCommandWith(t, Dependencies{HTTPClient: client}, "--workspace", "ws-two", "query", "SELECT 1 AS ready")
	require.NoError(t, err)
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ws-one", state.WorkspaceID)
	require.Equal(t, "ws-two", state.DataTokenWorkspaceID)
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	cfg, err := config.Read(paths)
	require.NoError(t, err)
	require.Equal(t, "ws-one", cfg.Connections["default"].WorkspaceID)
	_, _, err = runCommandWith(t, Dependencies{HTTPClient: client}, "query", "SELECT 1 AS ready")
	require.NoError(t, err)
	require.Equal(t, []string{"ws-two.example.com", "ws-one.example.com"}, endpoints)
	_, _, err = runCommand(t, "--workspace", "missing", "auth", "status")
	require.ErrorIs(t, err, auth.ErrWorkspaceUnavailable)
	cfg, err = config.Read(paths)
	require.NoError(t, err)
	require.Equal(t, "ws-one", cfg.Connections["default"].WorkspaceID)
	_, _, err = runCommand(t, "--workspace", "ws-two", "workspace", "use", "ws-one")
	require.Error(t, err)
}

func TestNamedProfileConfigurationMigratesWithoutNewLogin(t *testing.T) {
	fake, store := setupCLITest(t)
	before := saveStoredLogin(t, store, fake.URL, "ws-one")
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	legacy := `current_profile = "default"
[profiles.default]
control_url = "` + fake.URL + `"
console_url = "https://console.example.com"
workspace_id = "ws-one"
`
	require.NoError(t, os.WriteFile(paths.Config, []byte(legacy), 0600))
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-one", "One")}
	fake.Details["ws-one"] = controlplane.WorkspaceDetails{Workspace: fake.Workspaces[0]}
	_, _, err = runCommand(t, "auth", "status")
	require.NoError(t, err)
	after, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, before.RefreshToken, after.RefreshToken)
	raw, err := os.ReadFile(paths.Config)
	require.NoError(t, err)
	require.Contains(t, string(raw), "[connections.default]")
	require.NotContains(t, string(raw), "[profiles.")
	require.Empty(t, fake.RevokedTokens)
	require.Zero(t, fake.DevicePolls)
}

func TestRemovalDuringAuthorizationDoesNotRecreateConnection(t *testing.T) {
	fake, _ := setupCLITest(t)
	_, _, err := runCommand(t, "connection", "add", "work")
	require.NoError(t, err)
	removed := make(chan error, 1)
	fake.TokenResponseMutate = func(_ *controlplane.TokenSet) {
		root := NewRoot(Dependencies{In: strings.NewReader(""), Out: io.Discard, ErrOut: io.Discard, Getenv: func(string) string { return "" }})
		root.SetArgs([]string{"connection", "remove", "work", "--yes"})
		removed <- root.ExecuteContext(t.Context())
	}
	_, _, err = runCommand(t, "--connection", "work", "auth", "login", "--use-device-code", "--no-browser")
	require.Error(t, err)
	require.NoError(t, <-removed)
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	cfg, err := config.Read(paths)
	require.NoError(t, err)
	require.Empty(t, cfg.Connections)
	require.Equal(t, []string{fake.RefreshToken}, fake.RevokedTokens)
}

func TestFailedAPIKeyConfigurationWriteRemovesNewSecret(t *testing.T) {
	_, _ = setupCLITest(t)
	var saved credential.Store
	deps := Dependencies{In: strings.NewReader("new-key-secret"), CredentialStore: func(kind string, paths config.Paths, reference string) (credential.Store, error) {
		store, err := credential.New(kind, paths, reference)
		if err != nil {
			return nil, err
		}
		if kind == credential.SourceKeyring && reference == config.CredentialReference(paths, "job") {
			saved = store
			return &interruptSaveStore{Store: store, afterSave: func() error { return os.Mkdir(paths.Config, 0700) }}, nil
		}
		return store, nil
	}}
	out, diagnostics, err := runCommandWith(t, deps, "connection", "add", "job", "--auth-type", "api_key", "--endpoint", "https://job.example.com", "--api-key-stdin")
	require.Error(t, err)
	require.NotContains(t, out+diagnostics+err.Error(), "new-key-secret")
	require.NotNil(t, saved)
	_, err = saved.Load("https://job.example.com")
	require.ErrorIs(t, err, credential.ErrNotFound)
}
