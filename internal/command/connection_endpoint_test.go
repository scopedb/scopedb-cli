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

	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyConnectionsShareEndpoint(t *testing.T) {
	for _, backend := range []string{"keyring", "plaintext"} {
		t.Run(backend, func(t *testing.T) {
			_, _ = setupCLITest(t)
			for _, name := range []string{"first", "second"} {
				args := []string{"connection", "add", name, "--auth-type", "api_key", "--endpoint", "https://api.example.com", "--api-key-stdin"}
				if backend == "plaintext" {
					args = append(args, "--insecure-storage")
				}
				_, _, err := runCommandWith(t, Dependencies{In: strings.NewReader(name + "-key")}, args...)
				require.NoError(t, err)
			}
			var keys []string
			deps := Dependencies{HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				require.Equal(t, "api.example.com", r.URL.Host)
				keys = append(keys, r.Header.Get("Authorization"))
				return finishedQueryResponse(r), nil
			})}}
			for _, name := range []string{"first", "second", "first"} {
				_, _, err := runCommandWith(t, deps, "-c", name, "query", "SELECT 1 AS ready")
				require.NoError(t, err)
			}
			_, _, err := runCommand(t, "connection", "remove", "first", "--yes")
			require.NoError(t, err)
			_, _, err = runCommandWith(t, deps, "-c", "second", "query", "SELECT 1 AS ready")
			require.NoError(t, err)
			require.Equal(t, []string{"Bearer first-key", "Bearer second-key", "Bearer first-key", "Bearer second-key"}, keys)
			_, _, err = runCommandWith(t, deps, "-c", "first", "query", "SELECT 1 AS ready")
			require.ErrorIs(t, err, config.ErrUnknownConnection)
			require.Len(t, keys, 4)
		})
	}
}

func TestOAuthDiscoversEndpointsIndependentlyOfWorkspaceTokens(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-one", "One"), workspaceFixture("ws-two", "Two")}
	for _, w := range fake.Workspaces {
		fake.Details[w.ID] = controlplane.WorkspaceDetails{
			Workspace: w, Connection: controlplane.Connection{APIBaseURL: "https://api.example.com"},
			Provisioning: controlplane.Provisioning{Status: "ready"},
		}
	}
	saveStoredLogin(t, store, fake.URL, "ws-one")
	var exchanges, requests []string
	deps := Dependencies{HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/token-exchange") {
			workspaceID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/workspaces/"), "/token-exchange")
			exchanges = append(exchanges, workspaceID)
			body, err := json.Marshal(controlplane.TokenExchangeResponse{AccessToken: "token-" + workspaceID, TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)})
			require.NoError(t, err)
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
		}
		if strings.HasSuffix(r.URL.Host, ".example.com") {
			requests = append(requests, r.URL.Host+" "+r.Header.Get("Authorization"))
			return finishedQueryResponse(r), nil
		}
		return http.DefaultTransport.RoundTrip(r)
	})}}
	for _, args := range [][]string{
		{"query", "SELECT 1 AS ready"},
		{"--workspace", "ws-two", "query", "SELECT 1 AS ready"},
		{"query", "SELECT 1 AS ready"},
	} {
		_, _, err := runCommandWith(t, deps, args...)
		require.NoError(t, err)
	}
	// A current token remains workspace-scoped when the service returns a new address.
	details := fake.Details["ws-one"]
	details.Connection.APIBaseURL = "https://new-api.example.com"
	fake.Details["ws-one"] = details
	_, _, err := runCommandWith(t, deps, "query", "SELECT 1 AS ready")
	require.NoError(t, err)
	require.Equal(t, []string{"ws-one", "ws-two", "ws-one"}, exchanges)
	require.Equal(t, []string{
		"api.example.com Bearer token-ws-one",
		"api.example.com Bearer token-ws-two",
		"api.example.com Bearer token-ws-one",
		"new-api.example.com Bearer token-ws-one",
	}, requests)
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "ws-one", state.WorkspaceID)
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	cfg, err := config.Read(paths)
	require.NoError(t, err)
	require.Equal(t, "ws-one", cfg.Connections["default"].WorkspaceID)
	raw, err := os.ReadFile(paths.Config)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "api.example.com", "OAuth configuration must not pin a discovered data address")
}
