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

package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientSessionRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, http.MethodGet, request.Method)
		assert.Equal(t, "/api/session", request.URL.Path)
		assert.Equal(t, "Bearer session-secret", request.Header.Get("Authorization"))
		assert.Equal(t, "scope/test", request.Header.Get("User-Agent"))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"user":{"email":"dev@example.com","created_at":"2026-09-09T00:00:00Z"},"workspaces":[{"id":"ws-1","display_name":"Production","role":"owner"}],"current_workspace_id":"ws-1"}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, "scope/test", server.Client())
	require.NoError(t, err)
	session, err := client.GetSession(t.Context(), "session-secret")
	require.NoError(t, err)
	require.Equal(t, "dev@example.com", session.User.Email)
	require.Equal(t, "ws-1", session.CurrentWorkspaceID)
	require.Len(t, session.Workspaces, 1)
}

func TestClientSendsLoginVerificationContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, http.MethodPost, request.Method)
		assert.Equal(t, "/api/login/verify", request.URL.Path)
		var body map[string]string
		assert.NoError(t, json.NewDecoder(request.Body).Decode(&body))
		assert.Equal(t, map[string]string{"login_challenge": "challenge-1", "code": "123456"}, body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"token":"session-secret","workspace_id":"ws-1"}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, "", server.Client())
	require.NoError(t, err)
	response, err := client.VerifyLogin(t.Context(), "challenge-1", "123456")
	require.NoError(t, err)
	require.Equal(t, LoginResponse{Token: "session-secret", WorkspaceID: "ws-1"}, response)
}

func TestClientPreservesStructuredHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Retry-After", "7")
		writer.Header().Set("X-Request-ID", "header-request")
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = writer.Write([]byte(`{"message":"slow down","request_id":"body-request"}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, "", server.Client())
	require.NoError(t, err)
	err = client.Health(t.Context())
	var apiErr *Error
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, &Error{
		Status:     http.StatusTooManyRequests,
		Message:    "slow down",
		RequestID:  "body-request",
		Retryable:  true,
		RetryAfter: 7 * time.Second,
	}, apiErr)
}

func TestClientEscapesWorkspacePath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/api/workspaces/a%20workspace", request.URL.EscapedPath())
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"workspace":{"id":"a workspace","role":"owner"},"connection":{},"placement":{},"provisioning":{"status":"pending"}}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, "", server.Client())
	require.NoError(t, err)
	_, err = client.GetWorkspace(t.Context(), "token", "a workspace")
	require.NoError(t, err)
}
