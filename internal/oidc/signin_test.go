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

package oidc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func environment(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestFromEnvironmentDetection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values map[string]string
		ok     bool
	}{
		{"empty", map[string]string{}, false},
		{"workspace only", map[string]string{"SCOPEDB_WORKSPACE_ID": "ws-1"}, true},
		{"github request only", map[string]string{
			"ACTIONS_ID_TOKEN_REQUEST_URL":   "https://github.example.com/token",
			"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token",
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signIn, ok := FromEnvironment(environment(tc.values), nil)
			require.Equal(t, tc.ok, ok)
			if ok {
				require.Equal(t, strings.TrimSpace(tc.values["SCOPEDB_WORKSPACE_ID"]), signIn.WorkspaceID())
			}
		})
	}
}

func TestTokenRequestsGitHubAudience(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, http.MethodGet, request.Method)
		assert.Equal(t, "Bearer req-token", request.Header.Get("Authorization"))
		assert.Equal(t, "https://control.scopedb.cloud", request.URL.Query().Get("audience"))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"value":"ci.jwt.token","count":1}`))
	}))
	t.Cleanup(server.Close)

	signIn, ok := FromEnvironment(environment(map[string]string{
		"SCOPEDB_WORKSPACE_ID":           "ws-1",
		"ACTIONS_ID_TOKEN_REQUEST_URL":   server.URL + "?api-version=2.0",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token",
	}), server.Client())
	require.True(t, ok)
	token, err := signIn.Token(t.Context(), "https://control.scopedb.cloud")
	require.NoError(t, err)
	require.Equal(t, "ci.jwt.token", token)
}

func TestTokenErrors(t *testing.T) {
	tokenServer := func(t *testing.T, status int, body string) *httptest.Server {
		t.Helper()
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(status)
			_, _ = writer.Write([]byte(body))
		}))
		t.Cleanup(server.Close)
		return server
	}

	t.Run("no github environment", func(t *testing.T) {
		signIn, ok := FromEnvironment(environment(map[string]string{"SCOPEDB_WORKSPACE_ID": "ws-1"}), nil)
		require.True(t, ok)
		_, err := signIn.Token(t.Context(), "https://control.example.com")
		require.ErrorIs(t, err, ErrNoToken)
	})

	t.Run("incomplete github environment", func(t *testing.T) {
		signIn, ok := FromEnvironment(environment(map[string]string{
			"SCOPEDB_WORKSPACE_ID":         "ws-1",
			"ACTIONS_ID_TOKEN_REQUEST_URL": "https://github.example.com/token",
		}), nil)
		require.True(t, ok)
		_, err := signIn.Token(t.Context(), "https://control.example.com")
		require.ErrorIs(t, err, ErrNoToken)
	})

	t.Run("rejects non-https request URL", func(t *testing.T) {
		signIn, ok := FromEnvironment(environment(map[string]string{
			"ACTIONS_ID_TOKEN_REQUEST_URL":   "http://token.evil.example.com",
			"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token",
		}), nil)
		require.True(t, ok)
		_, err := signIn.Token(t.Context(), "https://control.example.com")
		require.Error(t, err)
	})

	t.Run("server failure", func(t *testing.T) {
		server := tokenServer(t, http.StatusForbidden, `{"message":"OIDC token request denied"}`)
		signIn, ok := FromEnvironment(environment(map[string]string{
			"ACTIONS_ID_TOKEN_REQUEST_URL":   server.URL,
			"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token",
		}), server.Client())
		require.True(t, ok)
		_, err := signIn.Token(t.Context(), "https://control.example.com")
		require.ErrorContains(t, err, "OIDC token request denied")
	})

	t.Run("missing value", func(t *testing.T) {
		server := tokenServer(t, http.StatusOK, `{"value":""}`)
		signIn, ok := FromEnvironment(environment(map[string]string{
			"ACTIONS_ID_TOKEN_REQUEST_URL":   server.URL,
			"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token",
		}), server.Client())
		require.True(t, ok)
		_, err := signIn.Token(t.Context(), "https://control.example.com")
		require.ErrorContains(t, err, "contained no token")
	})

	t.Run("oversized response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = io.Copy(writer, strings.NewReader(strings.Repeat("x", maxTokenResponseBytes+2)))
		}))
		t.Cleanup(server.Close)
		signIn, ok := FromEnvironment(environment(map[string]string{
			"ACTIONS_ID_TOKEN_REQUEST_URL":   server.URL,
			"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token",
		}), server.Client())
		require.True(t, ok)
		_, err := signIn.Token(t.Context(), "https://control.example.com")
		require.ErrorContains(t, err, "too large")
	})
}
