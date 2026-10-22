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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
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
	out, diagnostics, err := runInteractiveLogin(t, fake, "")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
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
			_, diagnostics, err := runLoginScenario(t, fake, loginScenario{
				input:         "\r",
				inputTerminal: true,
				errorTerminal: true,
				openURL: func(target string) error {
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
			require.ErrorContains(t, err, tc.wantError)
			_, loadErr := store.Load(fake.URL)
			require.ErrorIs(t, loadErr, credential.ErrNotFound)
			require.Empty(t, fake.TokenForms)
			require.NotContains(t, diagnostics, fake.AuthorizationCode)
		})
	}
}

func TestLoopbackLoginReportsDeniedAuthorization(t *testing.T) {
	fake, store := setupCLITest(t)
	out, diagnostics, err := runLoginScenario(t, fake, loginScenario{
		input:         "\r",
		inputTerminal: true,
		errorTerminal: true,
		openURL: func(target string) error {
			parsed, err := url.Parse(target)
			require.NoError(t, err)
			callback, err := url.Parse(parsed.Query().Get("redirect_uri"))
			require.NoError(t, err)
			query := callback.Query()
			query.Set("error", "access_denied")
			query.Set("error_description", "\x1b[31mforged\x1b[0m")
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
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(err))
	require.Contains(t, err.Error(), "denied")
	require.NotContains(t, out+diagnostics, "forged")
	_, loadErr := store.Load(fake.URL)
	require.ErrorIs(t, loadErr, credential.ErrNotFound)
}

func TestLoopbackLoginIgnoresAForgedErrorCallback(t *testing.T) {
	fake, store := setupCLITest(t)
	_, diagnostics, err := runLoginScenario(t, fake, loginScenario{
		input:         "\r",
		inputTerminal: true,
		errorTerminal: true,
		openURL: func(target string) error {
			parsed, err := url.Parse(target)
			require.NoError(t, err)
			callback, err := url.Parse(parsed.Query().Get("redirect_uri"))
			require.NoError(t, err)
			query := callback.Query()
			query.Set("error", "access_denied")
			query.Set("error_description", "\x1b[31mforged\x1b[0m")
			query.Set("state", "not-the-state")
			query.Set("iss", fake.Issuer)
			callback.RawQuery = query.Encode()
			response, err := http.Get(callback.String())
			if err != nil {
				return err
			}
			return response.Body.Close()
		},
	})
	require.ErrorContains(t, err, "did not belong to this request")
	require.NotContains(t, diagnostics, "forged")
	_, loadErr := store.Load(fake.URL)
	require.ErrorIs(t, loadErr, credential.ErrNotFound)
}

func TestDeviceLoginPollsUntilApproved(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.DeviceOutcomes = []string{"authorization_pending", "slow_down", ""}
	out, diagnostics, err := runDeviceLogin(t, fake)
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
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
			out, _, err := runDeviceLogin(t, fake)
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
	_, _, err := runDeviceLogin(t, fake)
	require.ErrorContains(t, err, "incomplete device authorization")
}

func TestDeviceLoginPrintsThePrefilledLinkAndKeepsTheCode(t *testing.T) {
	fake, _ := setupCLITest(t)
	out, diagnostics, err := runDeviceLogin(t, fake)
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
	require.Contains(t, diagnostics, "https://console.example.com/oauth/device#user_code=BCDF-GHJK-LMNP")
	require.Contains(t, diagnostics, "https://console.example.com/oauth/device and enter the code")
	require.Contains(t, diagnostics, "BCDF-GHJK-LMNP")
}

func TestDeviceLoginDoesNotOpenAutomatically(t *testing.T) {
	fake, _ := setupCLITest(t)
	out, diagnostics, err := runLoginScenario(t, fake, loginScenario{
		openURL: failLoopbackOpenURL,
		args:    []string{"auth", "login", "--insecure-storage"},
	})
	require.NoError(t, err)
	require.Equal(t, "Logged in as dev@example.com.\n", out)
	require.Contains(t, diagnostics, "https://console.example.com/oauth/device#user_code=BCDF-GHJK-LMNP")
}

func TestDeviceLoginFallsBackToThePlainVerificationURL(t *testing.T) {
	fake, _ := setupCLITest(t)
	empty := ""
	fake.DeviceCompleteURI = &empty
	_, diagnostics, err := runLoginScenario(t, fake, loginScenario{
		openURL: failLoopbackOpenURL,
		args:    []string{"auth", "login", "--insecure-storage"},
	})
	require.NoError(t, err)
	require.Contains(t, diagnostics, "open https://console.example.com/oauth/device and enter the code")
	require.NotContains(t, diagnostics, "#user_code=")
	require.Contains(t, diagnostics, "BCDF-GHJK-LMNP")
}

func TestDeviceLoginReportsTheServerLifetime(t *testing.T) {
	for _, tc := range []struct {
		seconds int64
		want    string
	}{
		{45, "expires in 45s"},
		{125, "expires in 2m5s"},
		{600, "expires in 10m"},
		{3660, "expires in 1h1m"},
	} {
		t.Run(fmt.Sprintf("%ds", tc.seconds), func(t *testing.T) {
			fake, _ := setupCLITest(t)
			fake.DeviceExpiresIn = tc.seconds
			_, diagnostics, err := runDeviceLogin(t, fake)
			require.NoError(t, err)
			require.Contains(t, diagnostics, "Waiting for authorization... ("+tc.want+"; Ctrl+C to cancel)")
		})
	}
}
func TestDeviceLoginSpinsTheWaitOnATerminal(t *testing.T) {
	fake, _ := setupCLITest(t)
	out, diagnostics, err := runDeviceLogin(t, fake)
	require.NoError(t, err)
	require.Contains(t, diagnostics, "\r")
	require.Contains(t, diagnostics, "Waiting for authorization")
	require.Contains(t, diagnostics, "\x1b[K")
	require.NotContains(t, out, "\x1b")
}
func TestLoginFallsBackToDeviceWhenTheBrowserCannotOpen(t *testing.T) {
	fake, store := setupCLITest(t)
	out, diagnostics, err := runLoginScenario(t, fake, loginScenario{
		inputTerminal: true,
		errorTerminal: true,
		openURL:       failLoopbackOpenURL,
	})
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
	require.Contains(t, diagnostics, "Could not open a browser; using a device code instead.")
	require.Contains(t, diagnostics, "BCDF-GHJK-LMNP")
	require.NotContains(t, diagnostics, "Open this URL to approve the login")
	require.Equal(t, 1, fake.DevicePolls)
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ort_refresh", state.RefreshToken)
}

func TestDiscoveryRejectsForeignIssuer(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.MetadataMutate = func(metadata *controlplane.AuthorizationServerMetadata) {
		metadata.Issuer = "https://elsewhere.example.com"
	}
	_, _, err := runInteractiveLogin(t, fake, "")
	require.ErrorContains(t, err, "issuer")
}

func TestDiscoveryRejectsForeignEndpoint(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.MetadataMutate = func(metadata *controlplane.AuthorizationServerMetadata) {
		metadata.TokenEndpoint = "https://elsewhere.example.com/oauth/token"
	}
	_, _, err := runInteractiveLogin(t, fake, "")
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
		_, _, err := runInteractiveLogin(t, fake, "")
		require.Error(t, err)
	}
}

func TestLoginWithoutOAuthSupportReportsGuidance(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	_, _, err := runInteractiveCommand(t, "--control-url", server.URL, "auth", "login", "--insecure-storage")
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "requires ScopeDB v0.23.0 or newer")
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

	out, diagnostics, err := runInteractiveLogin(t, fake, "")
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
	out, diagnostics, err := runInteractiveLogin(t, fake, "")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
	require.Contains(t, diagnostics, "awaiting approval")
	require.Contains(t, diagnostics, "scope console --open")
}

func TestLoginSelectsTheOnlyOwnedWorkspace(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
	out, diagnostics, err := runInteractiveLogin(t, fake, "")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
	require.Contains(t, out, "Using workspace Alpha (ws-1).")
	require.NotContains(t, diagnostics, "no workspaces")
	require.NotContains(t, diagnostics, "no workspace is selected")
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ws-1", state.WorkspaceID)
}
func TestLoginKeepsTheStoredSelection(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha"), workspaceFixture("ws-2", "Beta")}
	saveExpiredLogin(t, store, fake.URL, "ws-2")

	out, diagnostics, err := runInteractiveLogin(t, fake, "")
	require.NoError(t, err)
	require.Contains(t, out, "Keeping workspace Beta (ws-2).")
	require.NotContains(t, diagnostics, "no workspace is selected")
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ws-2", state.WorkspaceID)
	require.Equal(t, "ort_refresh", state.RefreshToken)
}
func TestLoginKeepsTheStoredSelectionWithoutWritingCredentials(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha"), workspaceFixture("ws-2", "Beta")}
	saveExpiredLogin(t, store, fake.URL, "ws-1")
	counting := &countingStore{Store: store}

	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In:              strings.NewReader("\r"),
		Out:             &out,
		ErrOut:          &diagnostics,
		Getenv:          func(string) string { return "" },
		Sleep:           func(time.Duration) {},
		OpenURL:         fake.authorizationURL(t),
		CredentialStore: func(_ string, _ config.Paths) (credential.Store, error) { return counting, nil },
		IsInputTerminal: func() bool { return true },
		IsErrorTerminal: func() bool { return true },
	})
	root.SetArgs([]string{"--control-url", fake.URL, "auth", "login", "--insecure-storage"})
	require.NoError(t, root.ExecuteContext(t.Context()))
	require.Contains(t, out.String(), "Keeping workspace Alpha (ws-1).")
	require.Equal(t, 1, counting.saves)
}

func TestLoginClearsASelectionScheduledForDeletion(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{
		scheduledForDeletionFixture("ws-1", "Alpha"),
		workspaceFixture("ws-2", "Beta"),
	}
	saveExpiredLogin(t, store, fake.URL, "ws-1")

	out, diagnostics, err := runInteractiveLogin(t, fake, "")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
	require.NotContains(t, diagnostics, "no workspace is selected")
	require.Contains(t, out, "Using workspace Beta (ws-2).")
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ws-2", state.WorkspaceID)
}

func TestLoginDoesNotSelectASingleWorkspaceScheduledForDeletion(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{scheduledForDeletionFixture("ws-1", "Alpha")}

	out, diagnostics, err := runInteractiveLogin(t, fake, "")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
	require.Contains(t, diagnostics, "no workspace is selected")
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Empty(t, state.WorkspaceID)
}

func TestLoginClearsAStaleSelection(t *testing.T) {
	fake, store := setupCLITest(t)
	saveExpiredLogin(t, store, fake.URL, "ws-1")

	out, diagnostics, err := runInteractiveLogin(t, fake, "")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
	require.Contains(t, diagnostics, "no workspaces")
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Empty(t, state.WorkspaceID)
}

func TestLoginSelectsTheOnlyWorkspaceOfTheNewAccount(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-2", "Beta")}
	saveExpiredLogin(t, store, fake.URL, "ws-1")

	out, _, err := runInteractiveLogin(t, fake, "")
	require.NoError(t, err)
	require.Contains(t, out, "Using workspace Beta (ws-2).")
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ws-2", state.WorkspaceID)
}

func TestLoginRefusesWhileALoginIsStored(t *testing.T) {
	fake, store := setupCLITest(t)
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, diagnostics, err := runInteractiveLogin(t, fake, "")
	require.Error(t, err)
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(NormalizeError(err)))
	require.Contains(t, clierror.Render(err), "already logged in as dev@example.com")
	require.Contains(t, clierror.Render(err), "run 'scope auth logout' first")
	require.Empty(t, out)
	require.NotContains(t, diagnostics, "Open this URL to approve the login")
	require.Empty(t, fake.AuthorizationQuery)
	require.Empty(t, fake.TokenForms)
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ort_refresh", state.RefreshToken)
	require.Equal(t, "ws-1", state.WorkspaceID)
}

func TestLoginPreservesAnotherLoginCompletedDuringAuthorization(t *testing.T) {
	fake, store := setupCLITest(t)
	var existing credential.State
	out, _, err := runLoginScenario(t, fake, loginScenario{openURL: func(target string) error {
		// Another process finishes login after this command's initial credential check.
		existing = saveStoredLogin(t, store, fake.URL, "ws-other")
		existing.AccessToken = "oat_other"
		existing.RefreshToken = "ort_other"
		require.NoError(t, store.Save(fake.URL, existing))
		var loadErr error
		existing, loadErr = store.Load(fake.URL)
		require.NoError(t, loadErr)
		return fake.authorizationURL(t)(target)
	}})
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(NormalizeError(err)))
	require.Empty(t, out)
	require.Contains(t, clierror.Render(err), "scope auth status")
	state, loadErr := store.Load(fake.URL)
	require.NoError(t, loadErr)
	require.Equal(t, existing, state)
	require.Equal(t, []string{"ort_refresh"}, fake.RevokedTokens)
}

func TestLoginRefreshRecoversTruncatedResponse(t *testing.T) {
	for _, failures := range []int32{1, 3} {
		t.Run(fmt.Sprintf("failures=%d", failures), func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.RefreshedAccessToken = "oat_rotated"
			fake.RefreshedRefreshToken = "ort_rotated"
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/token" {
					_ = r.ParseForm()
					if r.Form.Get("grant_type") == "refresh_token" {
						if r.Form.Get("refresh_token") != "ort_refresh" {
							t.Error("recovery must reuse the original refresh token")
						}
						if attempts.Add(1) <= failures {
							w.Header().Set("Content-Length", "1000")
							_, _ = w.Write([]byte(`{"access_token":"partial`))
							return
						}
					}
				}
				fake.serve(w, r)
			}))
			t.Cleanup(server.Close)
			fake.URL, fake.Issuer = server.URL, server.URL
			saveLogin(t, store, fake.URL, "", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

			_, _, err := runFakeCommand(t, fake, "auth", "status", "--format", "json")
			state, loadErr := store.Load(fake.URL)
			require.NoError(t, loadErr)
			if failures == 1 {
				require.NoError(t, err)
				require.EqualValues(t, 2, attempts.Load())
				require.Equal(t, "ort_rotated", state.RefreshToken)
			} else {
				require.ErrorContains(t, err, "unexpected EOF")
				require.EqualValues(t, 3, attempts.Load())
				require.Equal(t, "ort_refresh", state.RefreshToken)
			}
		})
	}
}

func TestLoginRefusesWithoutTheAccountWhenLookupFails(t *testing.T) {
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
	saveStoredLogin(t, store, fake.URL, "ws-1")

	out, _, err := runInteractiveLogin(t, fake, "")
	require.Error(t, err)
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(NormalizeError(err)))
	require.Contains(t, clierror.Render(err), "already logged in")
	require.NotContains(t, clierror.Render(err), "as dev@example.com")
	require.Contains(t, clierror.Render(err), "scope auth status")
	require.Empty(t, out)
}

func TestLoginReplacesALoginThatScopeDBRejects(t *testing.T) {
	fake, store := setupCLITest(t)
	var refreshes atomic.Int32
	controlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_ = r.ParseForm()
			if r.PostForm.Get("grant_type") == "refresh_token" {
				refreshes.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"invalid_grant"}`))
				return
			}
		}
		fake.serve(w, r)
	}))
	t.Cleanup(controlServer.Close)
	fake.URL = controlServer.URL
	fake.Issuer = controlServer.URL
	saveLogin(t, store, fake.URL, "ws-1", time.Now().Add(30*time.Second), time.Now().Add(24*time.Hour))

	out, _, err := runInteractiveLogin(t, fake, "")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
	require.Equal(t, int32(1), refreshes.Load())
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ort_refresh", state.RefreshToken)
}

func TestLoginWithoutWorkspacesReportsSetup(t *testing.T) {
	fake, store := setupCLITest(t)

	out, diagnostics, err := runInteractiveLogin(t, fake, "")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
	require.NotContains(t, out, "CURRENT")
	require.Contains(t, diagnostics, "no workspaces")
	require.Contains(t, diagnostics, "scope console --open")
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Empty(t, state.WorkspaceID)
}

type countingStore struct {
	credential.Store
	saves int
}

func (s *countingStore) Save(controlURL string, state credential.State) error {
	s.saves++
	return s.Store.Save(controlURL, state)
}

func TestLoginRollsBackFailedPersistence(t *testing.T) {
	fake, store := setupCLITest(t)
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In:              strings.NewReader("\r"),
		Out:             &out,
		ErrOut:          &diagnostics,
		Getenv:          func(string) string { return "" },
		Sleep:           func(time.Duration) {},
		OpenURL:         fake.authorizationURL(t),
		IsInputTerminal: func() bool { return true },
		IsErrorTerminal: func() bool { return true },
		CredentialStore: func(_ string, paths config.Paths) (credential.Store, error) {
			return &interruptSaveStore{Store: store, afterSave: func() error { return os.Mkdir(paths.Config, 0o700) }}, nil
		},
	})
	root.SetArgs([]string{"--control-url", fake.URL, "auth", "login", "--insecure-storage"})
	err = root.ExecuteContext(t.Context())
	require.Equal(t, clierror.ExitGeneral, clierror.ExitCode(NormalizeError(err)))
	require.Empty(t, out.String())
	require.Equal(t, []string{"ort_refresh"}, fake.RevokedTokens)
	_, loadErr := store.Load(fake.URL)
	require.ErrorIs(t, loadErr, credential.ErrNotFound)
	_ = paths
}

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

	out, _, err := runInteractiveLogin(t, fake, "")
	require.ErrorContains(t, err, "existing credentials could not be read")
	require.Empty(t, fake.RevokedTokens)
	require.Empty(t, out)
	preserved, err := os.ReadFile(paths.CredentialsFile)
	require.NoError(t, err)
	require.Equal(t, broken, string(preserved))
}

func TestLoginRecoversFromOlderStoredState(t *testing.T) {
	fake, store := setupCLITest(t)
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	legacy := `{"version":1,"profiles":{"` + profileKeyFor(fake.URL) + `":{"version":1,"control_url":"` + fake.URL + `","session_token":"legacy-secret"}}}`
	require.NoError(t, os.MkdirAll(paths.Directory, 0o700))
	require.NoError(t, os.WriteFile(paths.CredentialsFile, []byte(legacy), 0o600))

	out, _, err := runInteractiveLogin(t, fake, "")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
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

	_, _, err = runInteractiveCommand(t, "auth", "login", "--insecure-storage", "--control-url", controlURL)
	require.Error(t, err)
	rendered := clierror.Render(NormalizeError(err))
	require.Contains(t, rendered, "cannot reach ScopeDB control plane")
	require.Contains(t, rendered, "Caused by: ")
	require.Contains(t, rendered, "connection refused")
}

func TestLoginWithoutAnInteractiveTerminalSelectsFirstWorkspace(t *testing.T) {
	for _, flow := range []struct {
		name    string
		openURL func(string) error
	}{
		{name: "browser"},
		{name: "device", openURL: failLoopbackOpenURL},
	} {
		for _, terminal := range []struct {
			name        string
			input       bool
			diagnostics bool
		}{
			{name: "neither"},
			{name: "stdin only", input: true},
			{name: "stderr only", diagnostics: true},
		} {
			t.Run(flow.name+"/"+terminal.name, func(t *testing.T) {
				fake, store := setupCLITest(t)
				fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-2", "Beta"), workspaceFixture("ws-1", "Alpha")}
				out, diagnostics, err := runLoginScenario(t, fake, loginScenario{
					inputTerminal: terminal.input,
					errorTerminal: terminal.diagnostics,
					openURL:       flow.openURL,
				})
				require.NoError(t, err)
				require.Equal(t, "Logged in as dev@example.com.\nUsing workspace Alpha (ws-1).\n", out)
				require.NotContains(t, diagnostics, "no workspace is selected")
				if !terminal.diagnostics {
					require.NotContains(t, diagnostics, "\x1b")
				}
				state, err := store.Load(fake.URL)
				require.NoError(t, err)
				require.Equal(t, "ort_refresh", state.RefreshToken)
				require.Equal(t, "ws-1", state.WorkspaceID)
			})
		}
	}
}

func TestLoginDefaultsToBrowserInRemoteEnvironments(t *testing.T) {
	for _, variable := range []string{"SSH_CONNECTION", "KUBERNETES_SERVICE_HOST", "container"} {
		t.Run(variable, func(t *testing.T) {
			fake, store := setupCLITest(t)
			out, _, err := runLoginScenario(t, fake, loginScenario{
				getenv: func(name string) string {
					if name == variable {
						return "set"
					}
					return ""
				},
			})
			require.NoError(t, err)
			require.Contains(t, out, "Logged in as dev@example.com.")
			require.NotEmpty(t, fake.AuthorizationQuery)
			require.Zero(t, fake.DevicePolls)
			state, err := store.Load(fake.URL)
			require.NoError(t, err)
			require.Equal(t, "ort_refresh", state.RefreshToken)
		})
	}
}

func TestLoginSelectsFirstAvailableWorkspace(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{
		scheduledForDeletionFixture("ws-3", "Deleted"),
		workspaceFixture("ws-2", "Beta"),
		workspaceFixture("ws-1", "Alpha"),
	}
	out, _, err := runInteractiveLogin(t, fake, "")
	require.NoError(t, err)
	require.Contains(t, out, "Using workspace Alpha (ws-1).")
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ws-1", state.WorkspaceID)
}

func TestLoginSelectsRequestedWorkspaceByName(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha"), workspaceFixture("ws-2", "Beta")}

	out, _, err := runLoginScenario(t, fake, loginScenario{
		args: []string{"auth", "login", "--insecure-storage", "--workspace", "beta"},
	})
	require.NoError(t, err)
	require.Contains(t, out, "Using workspace Beta (ws-2).")
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ws-2", state.WorkspaceID)
}

func TestLoginSelectsRequestedWorkspaceByID(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha"), workspaceFixture("ws-2", "Beta")}

	out, _, err := runLoginScenario(t, fake, loginScenario{
		args: []string{"auth", "login", "--insecure-storage", "--workspace", "ws-2"},
	})
	require.NoError(t, err)
	require.Contains(t, out, "Using workspace Beta (ws-2).")
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ws-2", state.WorkspaceID)
}

func TestLoginRejectsUnknownRequestedWorkspace(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}

	out, _, err := runLoginScenario(t, fake, loginScenario{
		args: []string{"auth", "login", "--insecure-storage", "--workspace", "missing"},
	})
	require.Equal(t, clierror.ExitNotFound, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "login saved, but workspace missing was not selected")
	require.Contains(t, clierror.Render(err), "scope workspace use missing")
	require.Empty(t, out)
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Empty(t, state.WorkspaceID)
}

func TestLoginRejectsScheduledRequestedWorkspace(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{scheduledForDeletionFixture("ws-1", "Alpha"), workspaceFixture("ws-2", "Beta")}

	out, _, err := runLoginScenario(t, fake, loginScenario{
		args: []string{"auth", "login", "--insecure-storage", "--workspace", "ws-1"},
	})
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "login saved, but workspace ws-1 was not selected")
	require.Contains(t, clierror.Render(err), "scheduled for deletion")
	require.Empty(t, out)
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Empty(t, state.WorkspaceID)
}

func TestLoginReportsSelectedWorkspaceAsJSON(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-2", "Beta"), workspaceFixture("ws-1", "Alpha")}

	out, _, err := runLoginScenario(t, fake, loginScenario{
		args: []string{"auth", "login", "--insecure-storage", "--format", "json"},
	})
	require.NoError(t, err)
	require.JSONEq(t, `{"email":"dev@example.com","workspace":{"id":"ws-1","display_name":"Alpha","status":"ready","current":true}}`, out)
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ws-1", state.WorkspaceID)
}

func TestLoginReportsNoWorkspaceAsJSON(t *testing.T) {
	fake, store := setupCLITest(t)

	out, _, err := runLoginScenario(t, fake, loginScenario{
		args: []string{"auth", "login", "--insecure-storage", "--format", "json"},
	})
	require.NoError(t, err)
	require.JSONEq(t, `{"email":"dev@example.com"}`, out)
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Empty(t, state.WorkspaceID)
}

func TestLoginRequestedWorkspaceLookupFailureIsReported(t *testing.T) {
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

	out, _, err := runLoginScenario(t, fake, loginScenario{
		args: []string{"auth", "login", "--insecure-storage", "--workspace", "ws-1"},
	})
	require.Equal(t, clierror.ExitTemporary, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "login saved, but workspace ws-1 was not selected")
	require.Contains(t, clierror.Render(err), "scope workspace use ws-1")
	require.Empty(t, out)
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Empty(t, state.WorkspaceID)
}

func TestAPIKeyCommandsReportWorkspaceSetup(t *testing.T) {
	for _, phase := range []struct {
		name       string
		status     string
		workspaces []controlplane.Workspace
		hint       string
		exitCode   int
	}{
		{"pending", "pending", nil, "scope console --open", clierror.ExitAuth},
		{"no workspaces", "active", nil, "scope console --open", clierror.ExitUsage},
		{"no selection", "active", []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}, "scope workspace list", clierror.ExitUsage},
	} {
		t.Run(phase.name, func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.User.Status = phase.status
			fake.Workspaces = phase.workspaces
			saveStoredLogin(t, store, fake.URL, "")

			for _, args := range [][]string{
				{"api-key", "list"},
				{"api-key", "create", "automation"},
				{"api-key", "revoke", "automation", "--yes"},
			} {
				command := append([]string{"--control-url", fake.URL}, args...)
				out, _, err := runCommand(t, command...)
				require.Equal(t, phase.exitCode, clierror.ExitCode(err), "%v: %v", args, err)
				require.Empty(t, out)
				require.Contains(t, clierror.Render(err), phase.hint)
			}
		})
	}
}
