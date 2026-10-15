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
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/require"
)

func TestLoopbackLoginStoresTokens(t *testing.T) {
	fake, store := setupCLITest(t)
	out, diagnostics, err := runFakeCommand(t, fake, "auth", "login", "--insecure-storage", "--format", "json")
	require.NoError(t, err)
	require.JSONEq(t, `{"email":"dev@example.com"}`, out)
	require.Contains(t, diagnostics, "Open this URL to approve the login")

	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "oat_access", state.AccessToken)
	require.Equal(t, "ort_refresh", state.RefreshToken)
	require.False(t, state.AccessTokenExpiresAt.IsZero())
	require.False(t, state.RefreshTokenExpiresAt.IsZero())
	require.Empty(t, state.WorkspaceID)
	require.NotEmpty(t, fake.AuthorizationQuery.Get("code_challenge"))
	require.Equal(t, "S256", fake.AuthorizationQuery.Get("code_challenge_method"))
	require.Equal(t, controlplane.ClientID, fake.AuthorizationQuery.Get("client_id"))
	require.Equal(t, controlplane.ScopePlatform, fake.AuthorizationQuery.Get("scope"))
	require.NotEmpty(t, fake.TokenForms[0].Get("code_verifier"))
}

func TestLoopbackLoginRejectsMismatchedCallback(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     string
		issuer    string
		wantError string
	}{
		{"foreign state", "not-the-state", "", "did not belong to this request"},
		{"foreign issuer", "", "https://elsewhere.example.com", "no credentials were saved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, store := setupCLITest(t)
			var out, diagnostics bytes.Buffer
			root := NewRoot(Dependencies{
				Out: &out, ErrOut: &diagnostics,
				Getenv: func(string) string { return "" },
				Sleep:  func(time.Duration) {},
				OpenURL: func(target string) error {
					parsed, err := url.Parse(target)
					require.NoError(t, err)
					callback, err := url.Parse(parsed.Query().Get("redirect_uri"))
					require.NoError(t, err)
					query := callback.Query()
					query.Set("code", fake.AuthorizationCode)
					state := parsed.Query().Get("state")
					if tc.state != "" {
						state = tc.state
					}
					query.Set("state", state)
					issuer := fake.Issuer
					if tc.issuer != "" {
						issuer = tc.issuer
					}
					query.Set("iss", issuer)
					callback.RawQuery = query.Encode()
					response, err := http.Get(callback.String())
					if err != nil {
						return err
					}
					return response.Body.Close()
				},
			})
			root.SetArgs([]string{"--control-url", fake.URL, "auth", "login", "--insecure-storage"})
			require.ErrorContains(t, root.ExecuteContext(t.Context()), tc.wantError)
			_, loadErr := store.Load(fake.URL)
			require.ErrorIs(t, loadErr, credential.ErrNotFound)
			require.Empty(t, fake.TokenForms)
			require.NotContains(t, out.String()+diagnostics.String(), fake.AuthorizationCode)
		})
	}
}

func TestLoopbackLoginReportsDeniedAuthorization(t *testing.T) {
	fake, store := setupCLITest(t)
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		Out: &out, ErrOut: &diagnostics,
		Getenv: func(string) string { return "" },
		Sleep:  func(time.Duration) {},
		OpenURL: func(target string) error {
			parsed, err := url.Parse(target)
			require.NoError(t, err)
			callback, err := url.Parse(parsed.Query().Get("redirect_uri"))
			require.NoError(t, err)
			query := callback.Query()
			query.Set("error", "access_denied")
			query.Set("state", parsed.Query().Get("state"))
			query.Set("iss", fake.Issuer)
			callback.RawQuery = query.Encode()
			response, err := http.Get(callback.String())
			if err != nil {
				return err
			}
			return response.Body.Close()
		},
	})
	root.SetArgs([]string{"--control-url", fake.URL, "auth", "login", "--insecure-storage"})
	err := root.ExecuteContext(t.Context())
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(err))
	require.Contains(t, err.Error(), "denied")
	_, loadErr := store.Load(fake.URL)
	require.ErrorIs(t, loadErr, credential.ErrNotFound)
}

func TestDeviceLoginPollsUntilApproved(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.DeviceOutcomes = []string{"authorization_pending", "slow_down", ""}
	out, diagnostics, err := runFakeCommand(t, fake, "auth", "login", "--device", "--insecure-storage", "--format", "json")
	require.NoError(t, err)
	require.JSONEq(t, `{"email":"dev@example.com"}`, out)
	require.Contains(t, diagnostics, "BCDF-GHJK-LMNP")
	require.Equal(t, 3, fake.DevicePolls)
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ort_refresh", state.RefreshToken)
}

func TestDeviceLoginFailureOutcomes(t *testing.T) {
	for _, tc := range []struct {
		outcome   string
		wantError string
	}{
		{"access_denied", "denied"},
		{"expired_token", "expired"},
		{"invalid_grant", "can no longer be redeemed"},
	} {
		t.Run(tc.outcome, func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.DeviceOutcomes = []string{tc.outcome}
			out, _, err := runFakeCommand(t, fake, "auth", "login", "--device", "--insecure-storage")
			require.Equal(t, clierror.ExitAuth, clierror.ExitCode(err))
			require.Contains(t, err.Error(), tc.wantError)
			require.Empty(t, out)
			_, loadErr := store.Load(fake.URL)
			require.ErrorIs(t, loadErr, credential.ErrNotFound)
		})
	}
}

func TestDeviceLoginRejectsIncompleteResponse(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.UserCode = ""
	_, _, err := runFakeCommand(t, fake, "auth", "login", "--device", "--insecure-storage")
	require.ErrorContains(t, err, "incomplete device authorization")
}

func TestLoginRequiresDeviceInSSHSession(t *testing.T) {
	fake, store := setupCLITest(t)
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		Out: &out, ErrOut: &diagnostics,
		Sleep: func(time.Duration) {},
		Getenv: func(name string) string {
			if name == "SSH_CONNECTION" {
				return "10.0.0.2 52100 10.0.0.1 22"
			}
			return ""
		},
	})
	root.SetArgs([]string{"--control-url", fake.URL, "auth", "login", "--insecure-storage"})
	err := root.ExecuteContext(t.Context())
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "--device")
	_, loadErr := store.Load(fake.URL)
	require.ErrorIs(t, loadErr, credential.ErrNotFound)
}

func TestDiscoveryRejectsForeignIssuer(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.MetadataMutate = func(metadata *controlplane.AuthorizationServerMetadata) {
		metadata.Issuer = "https://elsewhere.example.com"
	}
	_, _, err := runFakeCommand(t, fake, "auth", "login", "--insecure-storage")
	require.ErrorContains(t, err, "issuer")
}

func TestDiscoveryRejectsForeignEndpoint(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.MetadataMutate = func(metadata *controlplane.AuthorizationServerMetadata) {
		metadata.TokenEndpoint = "https://elsewhere.example.com/oauth/token"
	}
	_, _, err := runFakeCommand(t, fake, "auth", "login", "--insecure-storage")
	require.ErrorContains(t, err, "token_endpoint")
}

func TestDiscoveryRequiresPKCEAndIssuerParameter(t *testing.T) {
	for _, mutate := range []func(*controlplane.AuthorizationServerMetadata){
		func(metadata *controlplane.AuthorizationServerMetadata) {
			metadata.CodeChallengeMethodsSupported = []string{"plain"}
		},
		func(metadata *controlplane.AuthorizationServerMetadata) {
			metadata.AuthorizationResponseIssParameterSupported = false
		},
	} {
		fake, _ := setupCLITest(t)
		fake.MetadataMutate = mutate
		_, _, err := runFakeCommand(t, fake, "auth", "login", "--insecure-storage")
		require.Error(t, err)
	}
}

func TestLoginWithoutOAuthSupportReportsGuidance(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	_, _, err := runCommand(t, "--control-url", server.URL, "auth", "login", "--insecure-storage")
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "does not offer CLI login")
	require.Contains(t, clierror.Render(err), "SCOPEDB_ENDPOINT and SCOPEDB_API_KEY")
}

func TestLoginKeepsCredentialsWhenAccountLookupFails(t *testing.T) {
	fake, store := setupCLITest(t)
	controlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/user" {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"message":"temporarily unavailable"}`))
			return
		}
		fake.serve(w, r)
	}))
	t.Cleanup(controlServer.Close)
	fake.URL = controlServer.URL
	fake.Issuer = controlServer.URL

	out, diagnostics, err := runFakeCommand(t, fake, "auth", "login", "--insecure-storage")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in.")
	require.Contains(t, diagnostics, "scope auth status")
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ort_refresh", state.RefreshToken)
}

func TestLoginReportsWorkspaceSetup(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.User.Status = "pending"
	out, diagnostics, err := runFakeCommand(t, fake, "auth", "login", "--insecure-storage")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
	require.Contains(t, diagnostics, "awaiting approval")
	require.Contains(t, diagnostics, "scope console --open")
}

func TestLoginReportsTheWorkspacesTheAccountOwns(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	out, diagnostics, err := runFakeCommand(t, fake, "auth", "login", "--insecure-storage")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
	require.NotContains(t, diagnostics, "no workspaces")
	require.Contains(t, diagnostics, "no workspace is selected")
}

func TestLoginRollsBackFailedPersistence(t *testing.T) {
	fake, store := setupCLITest(t)
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	// The first credential write succeeds and then blocks the configuration write, so the login
	// must be rolled back and its grant revoked.
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		Out: &out, ErrOut: &diagnostics,
		Getenv:  func(string) string { return "" },
		Sleep:   func(time.Duration) {},
		OpenURL: fake.authorizationURL(t),
		CredentialStore: func(_ string, paths config.Paths) (credential.Store, error) {
			return &interruptSaveStore{Store: store, afterSave: func() error { return os.Mkdir(paths.Config, 0o700) }}, nil
		},
	})
	root.SetArgs([]string{"--control-url", fake.URL, "auth", "login", "--insecure-storage", "--format", "json"})
	err = root.ExecuteContext(t.Context())
	require.Equal(t, clierror.ExitGeneral, clierror.ExitCode(NormalizeError(err)))
	require.Empty(t, out.String())
	require.Equal(t, []string{"ort_refresh"}, fake.RevokedTokens)
	_, loadErr := store.Load(fake.URL)
	require.ErrorIs(t, loadErr, credential.ErrNotFound)
	_ = paths
}

// interruptSaveStore fails every save after the first one succeeds.
type interruptSaveStore struct {
	credential.Store
	afterSave func() error
}

func (s *interruptSaveStore) Save(controlURL string, state credential.State) error {
	if err := s.Store.Save(controlURL, state); err != nil {
		return err
	}
	if interrupt := s.afterSave; interrupt != nil {
		s.afterSave = nil
		return interrupt()
	}
	return nil
}

func TestLoginPreservesUnreadableCredentialFile(t *testing.T) {
	fake, _ := setupCLITest(t)
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	const broken = `{"version":1,"profiles":`
	require.NoError(t, os.WriteFile(paths.CredentialsFile, []byte(broken), 0o600))

	out, _, err := runFakeCommand(t, fake, "auth", "login", "--insecure-storage")
	require.ErrorContains(t, err, "existing credentials could not be read")
	require.Equal(t, []string{"ort_refresh"}, fake.RevokedTokens)
	require.Empty(t, out)
	preserved, err := os.ReadFile(paths.CredentialsFile)
	require.NoError(t, err)
	require.Equal(t, broken, string(preserved))
}

func TestLoginRecoversFromOlderStoredState(t *testing.T) {
	fake, store := setupCLITest(t)
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	// Version 1 stored a browser session token, which an OAuth login can never use again.
	legacy := `{"version":1,"profiles":{"` + profileKeyFor(fake.URL) + `":{"version":1,"control_url":"` + fake.URL + `","session_token":"legacy-secret"}}}`
	require.NoError(t, os.MkdirAll(paths.Directory, 0o700))
	require.NoError(t, os.WriteFile(paths.CredentialsFile, []byte(legacy), 0o600))

	out, _, err := runFakeCommand(t, fake, "auth", "login", "--insecure-storage", "--format", "json")
	require.NoError(t, err)
	require.JSONEq(t, `{"email":"dev@example.com"}`, out)
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ort_refresh", state.RefreshToken)
	require.NotContains(t, out, "legacy-secret")
}

func TestLogoutRevokesAndRemovesCredentials(t *testing.T) {
	fake, store := setupCLITest(t)
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, diagnostics, err := runCommand(t, "--control-url", fake.URL, "auth", "logout", "--format", "json")
	require.NoError(t, err)
	require.JSONEq(t, `{"changed":true}`, out)
	require.Empty(t, diagnostics)
	require.Equal(t, []string{"ort_refresh"}, fake.RevokedTokens)
	_, loadErr := store.Load(fake.URL)
	require.ErrorIs(t, loadErr, credential.ErrNotFound)

	out, _, err = runCommand(t, "--control-url", fake.URL, "auth", "logout", "--format", "json")
	require.NoError(t, err)
	require.JSONEq(t, `{"changed":false}`, out)
}

func TestLogoutKeepsLocalRemovalWhenRevocationFails(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.RevokedStatus = http.StatusInternalServerError
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, _, err := runCommand(t, "--control-url", fake.URL, "auth", "logout", "--format", "json")
	require.Error(t, err)
	require.Empty(t, out)
	require.Contains(t, clierror.Render(err), "local credentials removed")
	require.Contains(t, clierror.Render(err), "revoked in the Console")
	_, loadErr := store.Load(fake.URL)
	require.ErrorIs(t, loadErr, credential.ErrNotFound)
}

func TestLogoutRejectsEnvironmentCredentials(t *testing.T) {
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
	root.SetArgs([]string{"auth", "logout", "--format", "json"})
	err := root.ExecuteContext(t.Context())
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	require.Empty(t, out.String())
	require.NotContains(t, diagnostics.String(), "machine-secret")
}

func TestLoginReportsUnreachableControlPlane(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	controlURL := "http://" + listener.Addr().String()
	require.NoError(t, listener.Close())

	_, _, err = runCommand(t, "auth", "login", "--insecure-storage", "--control-url", controlURL)
	require.Error(t, err)
	rendered := clierror.Render(NormalizeError(err))
	require.Contains(t, rendered, "cannot reach ScopeDB control plane")
	require.Contains(t, rendered, "Caused by: ")
	require.Contains(t, rendered, "connection refused")
}

func TestLoginDoesNotPrintSecrets(t *testing.T) {
	fake, _ := setupCLITest(t)
	out, diagnostics, err := runFakeCommand(t, fake, "auth", "login", "--insecure-storage", "--format", "json")
	require.NoError(t, err)
	combined := out + diagnostics
	for _, secret := range []string{"oat_access", "ort_refresh", fake.AuthorizationCode} {
		require.NotContains(t, combined, secret)
	}
}
