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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/require"
	keyring "github.com/zalando/go-keyring"
)

func TestKeyringFailureReportsRecoveryWithoutPlaintextFallback(t *testing.T) {
	for _, args := range [][]string{
		{"query", "SELECT 1 AS ready"},
		{"auth", "login"},
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

func TestLoginReportsKeyringWriteFailure(t *testing.T) {
	fake, _ := setupCLITest(t)
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")
	keyring.MockInit()
	t.Cleanup(keyring.MockInit)

	out, _, err := runLoginScenario(t, fake, loginScenario{
		args: []string{"auth", "login"},
		credentialStore: func(kind string, paths config.Paths) (credential.Store, error) {
			store, err := credential.New(kind, paths)
			return keyringWriteFailureStore{Store: store}, err
		},
	})
	require.ErrorContains(t, err, "credentials could not be stored")
	require.ErrorIs(t, err, os.ErrPermission)
	require.Equal(t, clierror.ExitGeneral, clierror.ExitCode(err))
	require.Empty(t, out)
	requireKeyringRecovery(t, clierror.Render(NormalizeError(err)))
	require.Equal(t, []string{"ort_refresh"}, fake.RevokedTokens)
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	require.NoFileExists(t, paths.Config)
	require.NoFileExists(t, paths.CredentialsFile)
}

type keyringWriteFailureStore struct{ credential.Store }

func (keyringWriteFailureStore) Save(string, credential.State) error {
	return &credential.KeyringError{Op: "write", Err: os.ErrPermission}
}

func TestQueryEnvironmentCredentialsBypassUnavailableKeyring(t *testing.T) {
	setupCLITest(t)
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")
	keyring.MockInitWithError(errors.New("D-Bus session is unavailable"))
	t.Cleanup(keyring.MockInit)
	var out, diagnostics bytes.Buffer
	queries := 0
	root := NewRoot(Dependencies{
		Out: &out, ErrOut: &diagnostics,
		Getenv: func(name string) string {
			switch name {
			case "SCOPEDB_ENDPOINT":
				return "https://data.example.com"
			case "SCOPEDB_API_KEY":
				return "machine-secret"
			}
			return ""
		},
		HTTPClient: &http.Client{Transport: doctorTransport(func(r *http.Request) (*http.Response, error) {
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
	})
	root.SetArgs([]string{"query", "SELECT 1 AS ready", "--format", "json"})
	require.NoError(t, root.ExecuteContext(t.Context()))
	require.Equal(t, 1, queries)
	require.JSONEq(t, `[{"ready":1}]`, out.String())
	require.Empty(t, diagnostics.String())
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
	require.Contains(t, diagnostics, "credentials will be stored unencrypted")
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
