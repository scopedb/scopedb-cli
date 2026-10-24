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
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/require"
	keyring "github.com/zalando/go-keyring"
)

func TestKeyringReadFailureReportsRecoveryWithoutCreatingCredentials(t *testing.T) {
	for _, args := range [][]string{
		{"query", "SELECT 1 AS ready"},
		{"doctor", "--format", "json"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			fake, _ := setupCLITest(t)
			t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")
			unavailable := errors.New("D-Bus session is unavailable")
			keyring.MockInitWithError(unavailable)
			t.Cleanup(keyring.MockInit)

			out, diagnostics, err := runFakeCommand(t, fake, args...)
			require.Equal(t, clierror.ExitGeneral, clierror.ExitCode(err))
			require.Empty(t, diagnostics)
			rendered := clierror.Render(NormalizeError(err))
			if args[0] == "doctor" {
				var report doctorReport
				require.NoError(t, json.Unmarshal([]byte(out), &report))
				require.False(t, report.OK)
				for _, check := range report.Checks {
					if check.Name == "authentication" {
						require.Equal(t, "fail", check.Status)
						rendered = check.Details
					}
				}
			} else {
				require.ErrorIs(t, err, unavailable)
				require.Empty(t, out)
			}
			require.Contains(t, rendered, unavailable.Error())
			requireKeyringRecovery(t, rendered)
			require.Empty(t, fake.TokenForms)
			paths, err := config.ResolvePaths()
			require.NoError(t, err)
			require.NoFileExists(t, paths.Config)
			require.NoFileExists(t, paths.CredentialsFile)
		})
	}
}

func TestMissingKeyringEntryReportsNotLoggedIn(t *testing.T) {
	fake, _ := setupCLITest(t)
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")
	keyring.MockInit()
	t.Cleanup(keyring.MockInit)

	_, _, err := runFakeCommand(t, fake, "query", "SELECT 1 AS ready")
	require.ErrorIs(t, err, auth.ErrNotLoggedIn)
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "scope auth login")
	require.NotContains(t, clierror.Render(err), "--insecure-storage")
}

func TestLoginFallsBackWhenKeyringWriteFails(t *testing.T) {
	fake, _ := setupCLITest(t)
	out, diagnostics, err := runLoginScenario(t, fake, loginScenario{
		args: []string{"auth", "login"},
		credentialStore: func(kind string, paths config.Paths) (credential.Store, error) {
			store, err := credential.New(kind, paths)
			if kind == credential.SourceKeyring {
				return credentialWriteFailureStore{Store: store, err: &credential.KeyringError{Op: "write", Err: os.ErrPermission}}, err
			}
			return store, err
		},
	})
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
	require.Contains(t, diagnostics, "falling back to plaintext")
	require.Empty(t, fake.RevokedTokens)
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	require.Contains(t, diagnostics, paths.CredentialsFile)
	require.FileExists(t, paths.CredentialsFile)
	saved, err := os.ReadFile(paths.Config)
	require.NoError(t, err)
	require.NotContains(t, string(saved), "credential_store")
}

type credentialWriteFailureStore struct {
	credential.Store
	err error
}

func (s credentialWriteFailureStore) Save(string, credential.State) error { return s.err }

func TestQueryEnvironmentCredentialsBypassUnavailableKeyring(t *testing.T) {
	setupCLITest(t)
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")
	keyring.MockInitWithError(errors.New("D-Bus session is unavailable"))
	t.Cleanup(keyring.MockInit)
	queries := 0
	out, diagnostics, err := runCommandWith(t, Dependencies{
		Getenv: func(name string) string {
			switch name {
			case "SCOPEDB_ENDPOINT":
				return "https://data.example.com"
			case "SCOPEDB_API_KEY":
				return "machine-secret"
			}
			return ""
		},
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			queries++
			require.Equal(t, "https://data.example.com/v1/statements", r.URL.String())
			require.Equal(t, "Bearer machine-secret", r.Header.Get("Authorization"))
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(doctorQueryResult)),
				Request:    r,
			}, nil
		})},
	}, "query", "SELECT 1 AS ready", "--format", "json")
	require.NoError(t, err)
	require.Equal(t, 1, queries)
	require.JSONEq(t, `[{"ready":1}]`, out)
	require.Empty(t, diagnostics)
}

func TestDeviceLoginWithExplicitPlaintextBypassesUnavailableKeyring(t *testing.T) {
	fake, _ := setupCLITest(t)
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")
	keyring.MockInitWithError(os.ErrPermission)
	t.Cleanup(keyring.MockInit)
	out, diagnostics, err := runLoginScenario(t, fake, loginScenario{
		openURL: func(string) error {
			t.Fatal("headless login must not open a browser")
			return nil
		},
		args: []string{"auth", "login", "--use-device-code", "--no-browser", "--insecure-storage"},
	})
	require.NoError(t, err)
	require.Equal(t, "Logged in as dev@example.com.\n", out)
	require.Contains(t, diagnostics, "credentials are stored unencrypted")
	require.Contains(t, diagnostics, "https://console.example.com/oauth/device#user_code=BCDF-GHJK-LMNP")

	out, _, err = runFakeCommand(t, fake, "auth", "status", "--format", "json")
	require.NoError(t, err)
	var status statusView
	require.NoError(t, json.Unmarshal([]byte(out), &status))
	require.Equal(t, "plaintext", status.CredentialSource)
}

func requireKeyringRecovery(t *testing.T, rendered string) {
	t.Helper()
	require.Contains(t, rendered, "SCOPEDB_ENDPOINT")
	require.Contains(t, rendered, "SCOPEDB_API_KEY")
	require.Contains(t, rendered, "unencrypted")
	require.Equal(t, 1, strings.Count(rendered, "scope auth login --insecure-storage"))
}

func TestLoginStorageChoiceDoesNotChangeNextLoginDefault(t *testing.T) {
	for _, flag := range []string{"", "--insecure-storage=false"} {
		t.Run("next login "+flag, func(t *testing.T) {
			fake, plaintext := setupCLITest(t)
			t.Setenv("SCOPEDB_CREDENTIAL_STORE", "plaintext")
			out, diagnostics, err := runLoginScenario(t, fake, loginScenario{
				args: []string{"auth", "login", "--insecure-storage", "--format", "json"},
			})
			require.NoError(t, err)
			require.JSONEq(t, `{"email":"dev@example.com"}`, out)
			paths, err := config.ResolvePaths()
			require.NoError(t, err)
			require.Contains(t, diagnostics, paths.CredentialsFile)
			saved, err := os.ReadFile(paths.Config)
			require.NoError(t, err)
			require.NotContains(t, string(saved), "credential_store")

			state, err := plaintext.Load(fake.URL)
			require.NoError(t, err)
			state.AccessTokenExpiresAt = time.Now().Add(-time.Minute)
			require.NoError(t, plaintext.Save(fake.URL, state))
			out, _, err = runFakeCommand(t, fake, "auth", "status", "--format", "json")
			require.NoError(t, err)
			var status statusView
			require.NoError(t, json.Unmarshal([]byte(out), &status))
			require.Equal(t, credential.SourcePlaintext, status.CredentialSource)
			require.Equal(t, paths.CredentialsFile, status.CredentialFile)
			require.Equal(t, 1, fake.Refreshes)
			refreshed, err := plaintext.Load(fake.URL)
			require.NoError(t, err)
			require.Equal(t, fake.RefreshedRefreshToken, refreshed.RefreshToken)
			_, err = credential.NewKeyringStore().Load(fake.URL)
			require.ErrorIs(t, err, credential.ErrNotFound)

			_, _, err = runFakeCommand(t, fake, "auth", "logout")
			require.NoError(t, err)
			require.Equal(t, []string{fake.RefreshedRefreshToken}, fake.RevokedTokens)
			_, err = plaintext.Load(fake.URL)
			require.ErrorIs(t, err, credential.ErrNotFound)
			// An old config file and environment override do not pin future
			// logins to plaintext after upgrading.
			require.NoError(t, os.WriteFile(paths.Config, []byte("credential_store = \"plaintext\"\n"), 0o600))
			args := []string{"auth", "login"}
			if flag != "" {
				args = append(args, flag)
			}
			_, diagnostics, err = runLoginScenario(t, fake, loginScenario{args: args})
			require.NoError(t, err)
			require.NotContains(t, diagnostics, "unencrypted")
			_, err = plaintext.Load(fake.URL)
			require.ErrorIs(t, err, credential.ErrNotFound)
			stored, err := credential.NewKeyringStore().Load(fake.URL)
			require.NoError(t, err)
			require.Equal(t, fake.RefreshToken, stored.RefreshToken)
			out, _, err = runFakeCommand(t, fake, "auth", "status", "--format", "json")
			require.NoError(t, err)
			status = statusView{}
			require.NoError(t, json.Unmarshal([]byte(out), &status))
			require.Equal(t, credential.SourceKeyring, status.CredentialSource)
			require.Empty(t, status.CredentialFile)
		})
	}
}

func TestDefaultLoginFallsBackFromUnavailableKeyringAndLogsOut(t *testing.T) {
	fake, plaintext := setupCLITest(t)
	keyring.MockInitWithError(os.ErrPermission)
	_, diagnostics, err := runLoginScenario(t, fake, loginScenario{
		args: []string{"auth", "login", "--use-device-code", "--no-browser"},
	})
	require.NoError(t, err)
	require.Contains(t, diagnostics, "falling back to plaintext")
	require.Contains(t, diagnostics, "OS keyring cleanup could not be verified")
	_, _, err = runFakeCommand(t, fake, "auth", "status")
	require.NoError(t, err)
	_, _, err = runFakeCommand(t, fake, "auth", "logout")
	require.ErrorIs(t, err, os.ErrPermission)
	require.Equal(t, []string{fake.RefreshToken}, fake.RevokedTokens)
	cleared, err := plaintext.Load(fake.URL)
	require.NoError(t, err)
	require.True(t, cleared.Cleared)
	require.Empty(t, cleared.RefreshToken)
	_, _, err = runFakeCommand(t, fake, "auth", "status")
	require.ErrorIs(t, err, auth.ErrNotLoggedIn)
	keyring.MockInit()
	_, _, err = runFakeCommand(t, fake, "auth", "logout")
	require.NoError(t, err)
	_, err = plaintext.Load(fake.URL)
	require.ErrorIs(t, err, credential.ErrNotFound)
}

func TestLoginRefusesRenewableCredentialsInEitherStore(t *testing.T) {
	for _, source := range []string{credential.SourceKeyring, credential.SourcePlaintext} {
		t.Run(source, func(t *testing.T) {
			fake, plaintext := setupCLITest(t)
			state := saveStoredLogin(t, plaintext, fake.URL, "")
			args := []string{"auth", "login"}
			if source == credential.SourceKeyring {
				require.NoError(t, credential.NewKeyringStore().Save(fake.URL, state))
				require.NoError(t, plaintext.Delete(fake.URL))
				args = append(args, "--insecure-storage")
			}
			_, _, err := runLoginScenario(t, fake, loginScenario{args: args})
			require.Equal(t, clierror.ExitAuth, clierror.ExitCode(err))
			require.ErrorContains(t, err, "already logged in")
			require.Empty(t, fake.TokenForms)
		})
	}
}

func TestLoginRestoresPreviousStoreWhenConfigurationSaveFails(t *testing.T) {
	for _, previousSource := range []string{credential.SourceKeyring, credential.SourcePlaintext} {
		t.Run(previousSource, func(t *testing.T) {
			fake, plaintext := setupCLITest(t)
			previous := saveExpiredLogin(t, plaintext, fake.URL, "ws-previous")
			target := credential.SourceKeyring
			var oldStore credential.Store = plaintext
			var newStore credential.Store = credential.NewKeyringStore()
			args := []string{"auth", "login"}
			if previousSource == credential.SourceKeyring {
				oldStore, newStore = newStore, oldStore
				require.NoError(t, oldStore.Save(fake.URL, previous))
				require.NoError(t, plaintext.Delete(fake.URL))
				target = credential.SourcePlaintext
				args = append(args, "--insecure-storage")
			}
			_, _, err := runLoginScenario(t, fake, loginScenario{
				args: args,
				credentialStore: func(kind string, paths config.Paths) (credential.Store, error) {
					store, err := credential.New(kind, paths)
					if kind == target {
						return &interruptSaveStore{Store: store, afterSave: func() error {
							return os.Mkdir(paths.Config, 0o700)
						}}, err
					}
					return store, err
				},
			})
			require.ErrorContains(t, err, "configuration could not be stored")
			require.NotContains(t, err.Error(), "previous credentials could not be restored")
			restored, err := oldStore.Load(fake.URL)
			require.NoError(t, err)
			require.Equal(t, previous.RefreshToken, restored.RefreshToken)
			require.WithinDuration(t, previous.RefreshTokenExpiresAt, restored.RefreshTokenExpiresAt, 0)
			require.Equal(t, previous.WorkspaceID, restored.WorkspaceID)
			_, err = newStore.Load(fake.URL)
			require.ErrorIs(t, err, credential.ErrNotFound)
			require.Equal(t, []string{fake.RefreshToken}, fake.RevokedTokens)
		})
	}
}

func TestLoginRevokesUnusedGrantWhenBothStoresFail(t *testing.T) {
	fake, _ := setupCLITest(t)
	out, diagnostics, err := runLoginScenario(t, fake, loginScenario{
		args: []string{"auth", "login"},
		credentialStore: func(kind string, paths config.Paths) (credential.Store, error) {
			store, err := credential.New(kind, paths)
			failure := os.ErrPermission
			if kind == credential.SourceKeyring {
				failure = &credential.KeyringError{Op: "write", Err: failure}
			}
			return credentialWriteFailureStore{Store: store, err: failure}, err
		},
	})
	require.ErrorContains(t, err, "credentials could not be stored")
	require.Empty(t, out)
	require.NotContains(t, diagnostics, "credentials are stored")
	require.Equal(t, []string{fake.RefreshToken}, fake.RevokedTokens)
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	require.NoFileExists(t, paths.Config)
	require.NoFileExists(t, paths.CredentialsFile)
}

func TestRefreshFailureDoesNotMoveKeyringLoginToPlaintext(t *testing.T) {
	fake, plaintext := setupCLITest(t)
	state := saveLogin(t, plaintext, fake.URL, "", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	require.NoError(t, credential.NewKeyringStore().Save(fake.URL, state))
	require.NoError(t, plaintext.Delete(fake.URL))
	_, diagnostics, err := runCommandWith(t, Dependencies{
		CredentialStore: func(kind string, paths config.Paths) (credential.Store, error) {
			store, err := credential.New(kind, paths)
			if kind == credential.SourceKeyring {
				return credentialWriteFailureStore{Store: store, err: &credential.KeyringError{Op: "write", Err: os.ErrPermission}}, err
			}
			return store, err
		},
	}, "auth", "status")
	require.ErrorContains(t, err, "save refreshed credentials")
	require.Equal(t, 1, fake.Refreshes)
	require.NotContains(t, diagnostics, "falling back")
	_, err = plaintext.Load(fake.URL)
	require.ErrorIs(t, err, credential.ErrNotFound)
}
