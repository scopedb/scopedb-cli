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
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oidcEnvironment puts the process inside a CI job: a workspace target plus a
// provider-issued OIDC token.
func oidcEnvironment() func(string) string {
	values := map[string]string{
		"SCOPEDB_WORKSPACE_ID": "ws-1",
		"SCOPEDB_OIDC_TOKEN":   "ci.jwt.token",
	}
	return func(name string) string { return values[name] }
}

func oidcExchangeFixture() controlplane.OIDCExchangeResponse {
	return controlplane.OIDCExchangeResponse{
		AccessToken: "oidc-key",
		TokenType:   "Bearer",
		ExpiresIn:   1800,
		ExpiresAt:   time.Now().Add(30 * time.Minute).UTC(),
		WorkspaceID: "ws-1",
		Endpoint:    "https://data.example.com",
	}
}

func TestQueryWithOIDCExchange(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.OIDCExchange = oidcExchangeFixture()

	var apiKeys []string
	out, diagnostics, err := runCommandWith(t, Dependencies{
		Getenv: oidcEnvironment(),
		HTTPClient: fake.dataClient(func(r *http.Request) (*http.Response, error) {
			apiKeys = append(apiKeys, r.Header.Get("Authorization"))
			return finishedQueryResponse(r), nil
		}),
	}, "--control-url", fake.URL, "query", "--format", "json", "SELECT 1 AS ready")
	require.NoError(t, err)
	require.JSONEq(t, `[{"ready":1}]`, out)
	require.Equal(t, 1, fake.OIDCExchanges)
	require.Equal(t, []string{"ci.jwt.token"}, fake.OIDCTokens)
	// The data plane sees only the exchanged key.
	require.Equal(t, []string{"Bearer oidc-key"}, apiKeys)
	// Nothing is stored locally.
	paths, pathErr := config.ResolvePaths()
	require.NoError(t, pathErr)
	_, statErr := os.Stat(paths.CredentialsFile)
	require.True(t, os.IsNotExist(statErr))
	require.NotContains(t, diagnostics, "oidc-key")
}

// brokenStore stands in for a credential backend the host cannot serve, such
// as a CI runner without an OS keyring.
type brokenStore struct{ err error }

func (s *brokenStore) Load(string) (credential.State, error) { return credential.State{}, s.err }
func (s *brokenStore) Save(string, credential.State) error   { return s.err }
func (s *brokenStore) Delete(string) error                   { return s.err }

func TestQueryOIDCWithoutKeyring(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.OIDCExchange = oidcExchangeFixture()
	keyringFailure := &credential.KeyringError{Op: "read", Err: errors.New("no secret service")}

	var apiKeys []string
	out, _, err := runCommandWith(t, Dependencies{
		Getenv: oidcEnvironment(),
		CredentialStore: func(kind string, paths config.Paths) (credential.Store, error) {
			if kind == credential.SourceKeyring {
				return &brokenStore{err: keyringFailure}, nil
			}
			return credential.NewPlaintextStore(paths.CredentialsFile), nil
		},
		HTTPClient: fake.dataClient(func(r *http.Request) (*http.Response, error) {
			apiKeys = append(apiKeys, r.Header.Get("Authorization"))
			return finishedQueryResponse(r), nil
		}),
	}, "--control-url", fake.URL, "query", "--format", "json", "SELECT 1 AS ready")
	require.NoError(t, err)
	require.JSONEq(t, `[{"ready":1}]`, out)
	require.Equal(t, 1, fake.OIDCExchanges)
	require.Equal(t, []string{"Bearer oidc-key"}, apiKeys)
}

func TestQueryOIDCLoginTakesPrecedence(t *testing.T) {
	fake, _ := setupDataPlaneLogin(t, "https://data.example.com")
	var apiKeys []string
	_, _, err := runCommandWith(t, Dependencies{
		Getenv: oidcEnvironment(),
		HTTPClient: fake.dataClient(func(r *http.Request) (*http.Response, error) {
			apiKeys = append(apiKeys, r.Header.Get("Authorization"))
			return finishedQueryResponse(r), nil
		}),
	}, "--control-url", fake.URL, "query", "--format", "json", "SELECT 1 AS ready")
	require.NoError(t, err)
	require.Zero(t, fake.OIDCExchanges)
	require.Equal(t, []string{"Bearer fixture-secret"}, apiKeys)
}

func TestQueryOIDCMissingWorkspace(t *testing.T) {
	fake, _ := setupCLITest(t)
	getenv := func(name string) string {
		if name == "SCOPEDB_OIDC_TOKEN" {
			return "ci.jwt.token"
		}
		return ""
	}
	_, _, err := runCommandWith(t, Dependencies{Getenv: getenv}, "--control-url", fake.URL, "query", "SELECT 1")
	require.Error(t, err)
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "SCOPEDB_WORKSPACE_ID")
	require.Zero(t, fake.OIDCExchanges)
}

func TestQueryOIDCWithoutTokenSource(t *testing.T) {
	fake, _ := setupCLITest(t)
	_, _, err := runCommandWith(t, Dependencies{
		Getenv: func(name string) string {
			if name == "SCOPEDB_WORKSPACE_ID" {
				return "ws-1"
			}
			return ""
		},
	}, "--control-url", fake.URL, "query", "SELECT 1")
	require.Error(t, err)
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "SCOPEDB_OIDC_TOKEN")
	require.Zero(t, fake.OIDCExchanges)
}

func TestQueryOIDCRejectedToken(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.OIDCExchangeStatus = http.StatusUnauthorized
	_, _, err := runCommandWith(t, Dependencies{
		Getenv: oidcEnvironment(),
	}, "--control-url", fake.URL, "query", "SELECT 1")
	require.Error(t, err)
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(err))
	rendered := clierror.Render(err)
	require.Contains(t, rendered, "OIDC token was rejected")
	require.Contains(t, rendered, "trust policies")
}

func TestDoctorWithOIDCExchange(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.OIDCExchange = oidcExchangeFixture()
	out, _, err := runCommandWith(t, Dependencies{
		Getenv: oidcEnvironment(),
		HTTPClient: fake.dataClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "Bearer oidc-key", r.Header.Get("Authorization"))
			return finishedQueryResponse(r), nil
		}),
	}, "--control-url", fake.URL, "doctor", "--format", "json")
	require.NoError(t, err)
	require.Contains(t, out, "OIDC exchange")
	require.Equal(t, 1, fake.OIDCExchanges)
}
