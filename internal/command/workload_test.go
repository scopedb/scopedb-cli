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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/require"
)

type workloadEnv map[string]string

func (e workloadEnv) getenv(key string) string { return e[key] }

func runWorkloadLogin(t *testing.T, fake *fakeControlPlane, env workloadEnv, httpClient *http.Client, args ...string) (string, string, error) {
	t.Helper()
	return runWorkloadLoginDeps(t, fake, env, Dependencies{HTTPClient: httpClient}, args...)
}

func runWorkloadLoginDeps(t *testing.T, fake *fakeControlPlane, env workloadEnv, deps Dependencies, args ...string) (string, string, error) {
	t.Helper()
	if len(args) == 0 || args[0] != "auth" {
		args = append([]string{"auth", "login", "--workload-identity", "--insecure-storage"}, args...)
	}
	deps.Getenv = env.getenv
	return runCommandWith(t, deps, append([]string{"--control-url", fake.URL}, args...)...)
}

func TestWorkloadLoginStoresTheIssuedCredential(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.WorkloadExchange = workloadExchangeFixture("https://data.example.com")
	out, diagnostics, err := runWorkloadLogin(t, fake,
		workloadEnv{"SCOPEDB_OIDC_TOKEN": "oidc-env-token"}, nil, "--workspace", "ws-1")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as workload identity catalog-ci (repo:acme/infra:environment:production).")
	require.Contains(t, out, "Using workspace ws-1")
	require.NotContains(t, out+diagnostics, "oidc-env-token")
	require.NotContains(t, out+diagnostics, "sk_workload_key")
	require.Equal(t, []string{"Bearer oidc-env-token"}, fake.WorkloadBearer)

	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, credential.KindWorkload, state.Kind)
	require.Equal(t, "ws-1", state.WorkspaceID)
	require.Equal(t, "https://data.example.com", state.Endpoint)
	require.Equal(t, "sk_workload_key", state.APIKey)
	require.Equal(t, fake.WorkloadExchange.ExpiresAt, state.APIKeyExpiresAt)
	require.Empty(t, state.AccessToken)
	require.Empty(t, state.RefreshToken)
	require.Empty(t, state.DataToken)
	require.Equal(t, &credential.WorkloadIdentity{
		PolicyID: "wip_1", Name: "catalog-ci", Provider: "github",
		Subject: "repo:acme/infra:environment:production",
	}, state.Workload)
}

func TestWorkloadLoginReportsJSON(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.WorkloadExchange = workloadExchangeFixture("https://data.example.com")
	out, _, err := runWorkloadLogin(t, fake,
		workloadEnv{"SCOPEDB_OIDC_TOKEN": "oidc-env-token"}, nil, "--workspace", "ws-1", "--format", "json")
	require.NoError(t, err)
	require.JSONEq(t, `{
		"login_kind": "workload",
		"workspace_id": "ws-1",
		"endpoint": "https://data.example.com",
		"expires_at": "`+fake.WorkloadExchange.ExpiresAt.Format(time.RFC3339)+`",
		"identity": {
			"policy_id": "wip_1", "name": "catalog-ci", "provider": "github",
			"subject": "repo:acme/infra:environment:production"
		}
	}`, out)
	require.NotContains(t, out, "sk_workload_key")
	require.NotContains(t, out, "oidc-env-token")
}

func TestWorkloadLoginTokenSourcePrecedence(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "oidc")
	require.NoError(t, os.WriteFile(tokenFile, []byte("  oidc-file-token\n"), 0o600))
	fake, _ := setupCLITest(t)
	fake.WorkloadExchange = workloadExchangeFixture("https://data.example.com")

	_, _, err := runWorkloadLogin(t, fake, workloadEnv{
		"SCOPEDB_OIDC_TOKEN_FILE":        tokenFile,
		"SCOPEDB_OIDC_TOKEN":             "oidc-env-token",
		"ACTIONS_ID_TOKEN_REQUEST_URL":   "https://actions.example.com/oidc",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "github-request-token",
	}, nil, "--workspace", "ws-1")
	require.NoError(t, err)
	require.Equal(t, []string{"Bearer oidc-file-token"}, fake.WorkloadBearer)

	_, _, err = runWorkloadLogin(t, fake, workloadEnv{
		"SCOPEDB_OIDC_TOKEN":           "oidc-env-token",
		"ACTIONS_ID_TOKEN_REQUEST_URL": "https://actions.example.com/oidc",
	}, nil, "--workspace", "ws-1")
	require.NoError(t, err)
	require.Equal(t, "Bearer oidc-env-token", fake.WorkloadBearer[len(fake.WorkloadBearer)-1])
}

func TestWorkloadLoginRejectsAnEmptyTokenFile(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "oidc")
	require.NoError(t, os.WriteFile(tokenFile, []byte(" \n"), 0o600))
	fake, _ := setupCLITest(t)
	_, _, err := runWorkloadLogin(t, fake,
		workloadEnv{"SCOPEDB_OIDC_TOKEN_FILE": tokenFile}, nil, "--workspace", "ws-1")
	require.ErrorContains(t, err, "empty")
	require.Zero(t, fake.WorkloadCalls)
}

func TestWorkloadLoginRejectsAnOversizedToken(t *testing.T) {
	fake, _ := setupCLITest(t)
	_, _, err := runWorkloadLogin(t, fake,
		workloadEnv{"SCOPEDB_OIDC_TOKEN": strings.Repeat("a", maxOIDCTokenSize+1)}, nil, "--workspace", "ws-1")
	require.ErrorContains(t, err, "16 KiB")
	require.Zero(t, fake.WorkloadCalls)
}

func TestWorkloadLoginRequestsAGitHubToken(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.WorkloadExchange = workloadExchangeFixture("https://data.example.com")
	var gotRequest *http.Request
	github := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasPrefix(r.URL.String(), fake.URL+"/") {
			return http.DefaultTransport.RoundTrip(r)
		}
		gotRequest = r
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"count":1,"value":"oidc-github-token"}`)),
			Request:    r,
		}, nil
	})}

	_, _, err := runWorkloadLogin(t, fake, workloadEnv{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   "https://actions.example.com/oidc?api-version=2.0",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "github-request-token",
	}, github, "--workspace", "ws-1")
	require.NoError(t, err)
	require.NotNil(t, gotRequest)
	require.Equal(t, "Bearer github-request-token", gotRequest.Header.Get("Authorization"))
	require.Equal(t, fake.URL, gotRequest.URL.Query().Get("audience"))
	require.Equal(t, "2.0", gotRequest.URL.Query().Get("api-version"))
	require.Equal(t, []string{"Bearer oidc-github-token"}, fake.WorkloadBearer)
}

func TestWorkloadLoginWithoutATokenSource(t *testing.T) {
	fake, _ := setupCLITest(t)
	_, _, err := runWorkloadLogin(t, fake, workloadEnv{}, nil, "--workspace", "ws-1")
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "SCOPEDB_OIDC_TOKEN")
	require.Zero(t, fake.WorkloadCalls)
}

func TestWorkloadLoginFlagValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		wantError string
	}{
		{"no workspace", []string{}, "--workspace"},
		{"device code", []string{"--workspace", "ws-1", "--use-device-code"}, "cannot be combined"},
		{"no browser", []string{"--workspace", "ws-1", "--no-browser"}, "cannot be combined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, _ := setupCLITest(t)
			_, _, err := runWorkloadLogin(t, fake, workloadEnv{"SCOPEDB_OIDC_TOKEN": "oidc-env-token"}, nil, tc.args...)
			require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
			require.Contains(t, clierror.Render(err), tc.wantError)
			require.Zero(t, fake.WorkloadCalls)
		})
	}
}

func TestWorkloadLoginReportsAnUnsupportedDeployment(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.WorkloadStatus = http.StatusNotFound
	_, _, err := runWorkloadLogin(t, fake,
		workloadEnv{"SCOPEDB_OIDC_TOKEN": "oidc-env-token"}, nil, "--workspace", "ws-1")
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "does not support workload identity")
	require.NotContains(t, clierror.Render(err), "oidc-env-token")
}

func TestWorkloadLoginReportsARejectedToken(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.WorkloadStatus = http.StatusUnauthorized
	_, _, err := runWorkloadLogin(t, fake,
		workloadEnv{"SCOPEDB_OIDC_TOKEN": "oidc-env-token"}, nil, "--workspace", "ws-1")
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(err))
	require.NotContains(t, clierror.Render(err), "oidc-env-token")
	_, loadErr := store.Load(fake.URL)
	require.ErrorIs(t, loadErr, credential.ErrNotFound)
}

func TestWorkloadLoginRejectionHintsAtTheExpectedSubject(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.WorkloadScript = []workloadExchangeOutcome{{
		Status: http.StatusUnauthorized, RequestID: "req-wl-reject",
		Message: "workload identity token was rejected",
	}}
	var sleeps []time.Duration
	_, _, err := runWorkloadLoginDeps(t, fake,
		workloadEnv{"SCOPEDB_OIDC_TOKEN": "oidc-env-token"},
		Dependencies{Sleep: func(d time.Duration) { sleeps = append(sleeps, d) }},
		"--workspace", "ws-1")
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(err))
	rendered := clierror.Render(err)
	require.Contains(t, rendered, "check that workspace ws-1 is correct")
	require.Contains(t, rendered, "req-wl-reject")
	require.Equal(t, 1, fake.WorkloadCalls)
	require.Empty(t, sleeps)
}

func TestWorkloadLoginRetriesAnUnavailableExchange(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.WorkloadExchange = workloadExchangeFixture("https://data.example.com")
	fake.WorkloadScript = []workloadExchangeOutcome{
		{Status: http.StatusServiceUnavailable, RetryAfter: "5"},
		{Status: http.StatusOK},
	}
	var sleeps []time.Duration
	out, diagnostics, err := runWorkloadLoginDeps(t, fake,
		workloadEnv{"SCOPEDB_OIDC_TOKEN": "oidc-env-token"},
		Dependencies{Sleep: func(d time.Duration) { sleeps = append(sleeps, d) }},
		"--workspace", "ws-1")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as workload identity catalog-ci")
	require.Contains(t, diagnostics, "workload identity exchange failed; retrying in 5s (attempt 2 of 3)")
	require.Equal(t, []time.Duration{5 * time.Second}, sleeps)
	require.Equal(t, 2, fake.WorkloadCalls)
	state, loadErr := store.Load(fake.URL)
	require.NoError(t, loadErr)
	require.Equal(t, "sk_workload_key", state.APIKey)
}

func TestWorkloadLoginGivesUpWhenTheExchangeStaysUnavailable(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.WorkloadScript = []workloadExchangeOutcome{{Status: http.StatusServiceUnavailable, RetryAfter: "5"}}
	var sleeps []time.Duration
	_, diagnostics, err := runWorkloadLoginDeps(t, fake,
		workloadEnv{"SCOPEDB_OIDC_TOKEN": "oidc-env-token"},
		Dependencies{Sleep: func(d time.Duration) { sleeps = append(sleeps, d) }},
		"--workspace", "ws-1")
	require.Equal(t, clierror.ExitTemporary, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "retry after 5s")
	require.Contains(t, diagnostics, "retrying in 5s (attempt 3 of 3)")
	require.Equal(t, 3, fake.WorkloadCalls)
	require.Equal(t, []time.Duration{5 * time.Second, 5 * time.Second}, sleeps)
}

func TestWorkloadLoginDoesNotRetryACredentialLimit(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.WorkloadScript = []workloadExchangeOutcome{{
		Status: http.StatusTooManyRequests, Message: "too many active credentials for this workload identity",
	}}
	var sleeps []time.Duration
	_, _, err := runWorkloadLoginDeps(t, fake,
		workloadEnv{"SCOPEDB_OIDC_TOKEN": "oidc-env-token"},
		Dependencies{Sleep: func(d time.Duration) { sleeps = append(sleeps, d) }},
		"--workspace", "ws-1")
	require.Equal(t, clierror.ExitTemporary, clierror.ExitCode(err))
	require.Equal(t, 1, fake.WorkloadCalls)
	require.Empty(t, sleeps)
}

func TestWorkloadLoginCapsTheRetryWait(t *testing.T) {
	fake, _ := setupCLITest(t)
	fake.WorkloadExchange = workloadExchangeFixture("https://data.example.com")
	fake.WorkloadScript = []workloadExchangeOutcome{
		{Status: http.StatusServiceUnavailable, RetryAfter: "120"},
		{Status: http.StatusOK},
	}
	var sleeps []time.Duration
	_, diagnostics, err := runWorkloadLoginDeps(t, fake,
		workloadEnv{"SCOPEDB_OIDC_TOKEN": "oidc-env-token"},
		Dependencies{Sleep: func(d time.Duration) { sleeps = append(sleeps, d) }},
		"--workspace", "ws-1")
	require.NoError(t, err)
	require.Equal(t, []time.Duration{30 * time.Second}, sleeps)
	require.Contains(t, diagnostics, "retrying in 30s")
	require.Equal(t, 2, fake.WorkloadCalls)
}

func TestWorkloadLoginRefusesToReplaceAnOAuthLogin(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.WorkloadExchange = workloadExchangeFixture("https://data.example.com")
	saveStoredLogin(t, store, fake.URL, "ws-1")

	_, _, err := runWorkloadLogin(t, fake,
		workloadEnv{"SCOPEDB_OIDC_TOKEN": "oidc-env-token"}, nil, "--workspace", "ws-1")
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "logout")
	state, loadErr := store.Load(fake.URL)
	require.NoError(t, loadErr)
	require.Equal(t, "oat_access", state.AccessToken)
}

func TestWorkloadLoginReplacesAWorkloadCredential(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.WorkloadExchange = workloadExchangeFixture("https://data.example.com")
	saveWorkloadLogin(t, store, fake.URL, "ws-1")

	_, _, err := runWorkloadLogin(t, fake,
		workloadEnv{"SCOPEDB_OIDC_TOKEN": "oidc-env-token"}, nil, "--workspace", "ws-1")
	require.NoError(t, err)
	state, loadErr := store.Load(fake.URL)
	require.NoError(t, loadErr)
	require.Equal(t, credential.KindWorkload, state.Kind)
	require.Equal(t, "sk_workload_key", state.APIKey)
}

func TestWorkloadStatusShowsTheCredential(t *testing.T) {
	fake, store := setupCLITest(t)
	saveWorkloadLogin(t, store, fake.URL, "ws-1")

	out, _, err := runFakeCommand(t, fake, "auth", "status")
	require.NoError(t, err)
	for _, field := range []string{"workload", "catalog-ci", "github", "repo:acme/infra:environment:production", "ws-1", "https://data.example.com"} {
		require.Contains(t, out, field)
	}
	require.NotContains(t, out, "sk_workload_key")
	require.Zero(t, fake.ExchangeCalls)

	out, _, err = runFakeCommand(t, fake, "auth", "status", "--format", "json")
	require.NoError(t, err)
	var view map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &view))
	require.Equal(t, "workload", view["login_kind"])
	require.Equal(t, "ws-1", view["workspace_id"])
	require.Equal(t, "https://data.example.com", view["endpoint"])
	require.Equal(t, "catalog-ci", view["workload_policy"])
	require.Equal(t, "github", view["workload_provider"])
	require.Equal(t, "repo:acme/infra:environment:production", view["workload_subject"])
	require.NotEmpty(t, view["credential_expires_at"])
	require.NotContains(t, view, "email")
	require.NotContains(t, out, "sk_workload_key")
}

func TestWorkloadStatusWarnsWhenExpired(t *testing.T) {
	fake, store := setupCLITest(t)
	state := saveWorkloadLogin(t, store, fake.URL, "ws-1")
	state.APIKeyExpiresAt = time.Now().Add(-time.Minute).UTC()
	require.NoError(t, store.Save(fake.URL, state))

	out, diagnostics, err := runFakeCommand(t, fake, "auth", "status")
	require.NoError(t, err)
	require.Contains(t, diagnostics, "expired")
	require.NotContains(t, out+diagnostics, "sk_workload_key")
}

func TestWorkloadLogoutRemovesTheCredential(t *testing.T) {
	fake, store := setupCLITest(t)
	saveWorkloadLogin(t, store, fake.URL, "ws-1")

	out, _, err := runFakeCommand(t, fake, "auth", "logout")
	require.NoError(t, err)
	require.Contains(t, out, "Logged out.")
	_, loadErr := store.Load(fake.URL)
	require.ErrorIs(t, loadErr, credential.ErrNotFound)
	require.Empty(t, fake.RevokedTokens, "a workload login has no grant to revoke")
}

func TestAccountCommandsRejectAWorkloadLogin(t *testing.T) {
	for _, args := range [][]string{
		{"workspace", "list"},
		{"workspace", "use", "ws-2"},
		{"workspace", "get"},
		{"api-key", "list"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Alpha")}
			saveWorkloadLogin(t, store, fake.URL, "ws-1")

			_, _, err := runFakeCommand(t, fake, args...)
			require.Equal(t, clierror.ExitAuth, clierror.ExitCode(err))
			require.Contains(t, clierror.Render(err), "workload")
			require.Zero(t, fake.Refreshes, "a workload login must not attempt an OAuth refresh")
		})
	}
}

func TestQueryUsesTheWorkloadCredential(t *testing.T) {
	fake, store := setupCLITest(t)
	saveWorkloadLogin(t, store, fake.URL, "ws-1")
	requests := 0
	_, _, err := runCommandWith(t, Dependencies{
		HTTPClient: fake.dataClient(func(r *http.Request) (*http.Response, error) {
			require.Equal(t, "https://data.example.com/v1/statements", r.URL.String())
			require.Equal(t, "Bearer sk_workload_key", r.Header.Get("Authorization"))
			requests++
			return finishedQueryResponse(r), nil
		}),
	}, "--control-url", fake.URL, "query", "SELECT 1 AS ready", "--format", "json")
	require.NoError(t, err)
	require.Equal(t, 1, requests)
	require.Zero(t, fake.ExchangeCalls, "a workload login must not call the OAuth token exchange")
	require.Zero(t, fake.Refreshes)
}

func TestExpiredWorkloadCredentialFailsWithAReloginHint(t *testing.T) {
	fake, store := setupCLITest(t)
	state := saveWorkloadLogin(t, store, fake.URL, "ws-1")
	state.APIKeyExpiresAt = time.Now().Add(-time.Minute).UTC()
	require.NoError(t, store.Save(fake.URL, state))

	_, _, err := runFakeCommand(t, fake, "query", "SELECT 1 AS ready")
	require.Equal(t, clierror.ExitAuth, clierror.ExitCode(err))
	require.Contains(t, clierror.Render(err), "workload-identity")
	require.Zero(t, fake.Refreshes, "an expired workload credential must not attempt an OAuth refresh")
	require.Zero(t, fake.ExchangeCalls)
}
