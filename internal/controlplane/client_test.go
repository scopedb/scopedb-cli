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
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientUserAndWorkspaceContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "Bearer oat_token", request.Header.Get("Authorization"))
		assert.Equal(t, "scope/test", request.Header.Get("User-Agent"))
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/user":
			assert.Equal(t, http.MethodGet, request.Method)
			_, _ = writer.Write([]byte(`{"id":"user-1","email":"dev@example.com","status":"active","introduction":"","created_at":"2026-09-09T00:00:00Z","workspace_limit":3}`))
		case "/api/workspaces":
			assert.Equal(t, http.MethodGet, request.Method)
			_, _ = writer.Write([]byte(`{"workspaces":[{"id":"ws-1","display_name":"Production","provider":"aws","region":"us-east-1","provisioning_status":"ready","scheduled_for_deletion_at":null}]}`))
		default:
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.Path)
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, "scope/test", server.Client())
	require.NoError(t, err)
	user, err := client.GetUser(t.Context(), "oat_token")
	require.NoError(t, err)
	require.Equal(t, "dev@example.com", user.Email)
	require.Equal(t, "active", user.Status)

	workspaces, err := client.ListWorkspaces(t.Context(), "oat_token")
	require.NoError(t, err)
	require.Len(t, workspaces, 1)
	require.Equal(t, "Production", workspaces[0].Name())
	require.False(t, workspaces[0].ScheduledForDeletion())
}

func TestClientCreateWorkspaceContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, http.MethodPost, request.Method)
		assert.Equal(t, "/api/workspaces", request.URL.Path)
		assert.Equal(t, "application/json", request.Header.Get("Content-Type"))
		var body CreateWorkspaceRequest
		assert.NoError(t, json.NewDecoder(request.Body).Decode(&body))
		assert.Equal(t, CreateWorkspaceRequest{DisplayName: "Analytics", Provider: "aws", Region: "us-east-1"}, body)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"token":"","workspace_id":"ws-new"}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, "", server.Client())
	require.NoError(t, err)
	created, err := client.CreateWorkspace(t.Context(), "oat_token", CreateWorkspaceRequest{
		DisplayName: "Analytics", Provider: "aws", Region: "us-east-1",
	})
	require.NoError(t, err)
	require.Equal(t, "ws-new", created.WorkspaceID)
	require.Empty(t, created.Token)
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
		_, _ = writer.Write([]byte(`{"workspace":{"id":"a workspace"},"connection":{},"placement":{},"provisioning":{"status":"pending"}}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, "", server.Client())
	require.NoError(t, err)
	_, err = client.GetWorkspace(t.Context(), "token", "a workspace")
	require.NoError(t, err)
}

func TestDiscoverOAuthValidatesMetadata(t *testing.T) {
	metadata := func(writer http.ResponseWriter, issuuer, token string) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"issuer":"` + issuuer + `","authorization_endpoint":"` + issuuer + `/oauth/authorize","device_authorization_endpoint":"` + issuuer + `/oauth/device/authorization","token_endpoint":"` + token + `","revocation_endpoint":"` + issuuer + `/oauth/revoke","code_challenge_methods_supported":["S256"],"authorization_response_iss_parameter_supported":true}`))
	}
	for _, tc := range []struct {
		name      string
		issuer    func(string) string
		token     func(string) string
		wantError string
	}{
		{"valid", func(u string) string { return u }, func(u string) string { return u + "/oauth/token" }, ""},
		{"foreign issuer", func(string) string { return "https://elsewhere.example.com" }, func(u string) string { return u + "/oauth/token" }, "issuer"},
		{"foreign token endpoint", func(u string) string { return u }, func(string) string { return "https://elsewhere.example.com/oauth/token" }, "token_endpoint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var base string
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				assert.Equal(t, metadataPath, request.URL.Path)
				metadata(writer, tc.issuer(base), tc.token(base))
			}))
			t.Cleanup(server.Close)
			base = server.URL

			client, err := NewClient(server.URL, "", server.Client())
			require.NoError(t, err)
			oauth, err := client.DiscoverOAuth(t.Context())
			if tc.wantError == "" {
				require.NoError(t, err)
				require.Equal(t, server.URL, oauth.Issuer())
			} else {
				require.ErrorContains(t, err, tc.wantError)
			}
		})
	}
}

func TestOAuthTokenRequestsUseTheFormContract(t *testing.T) {
	forms := make(chan url.Values, 4)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.NoError(t, request.ParseForm())
		forms <- request.PostForm
		assert.Equal(t, "application/x-www-form-urlencoded", request.Header.Get("Content-Type"))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"access_token":"oat_new","token_type":"Bearer","expires_in":3600,"refresh_token":"ort_new","refresh_token_expires_in":1209600,"scope":"platform"}`))
	}))
	t.Cleanup(server.Close)

	oauth := newOAuth(AuthorizationServerMetadata{
		Issuer:             server.URL,
		TokenEndpoint:      server.URL + "/oauth/token",
		RevocationEndpoint: server.URL + "/oauth/revoke",
	}, "", server.Client())

	_, err := oauth.ExchangeAuthorizationCode(t.Context(), "code-1", "http://127.0.0.1:1/callback", "verifier-1")
	require.NoError(t, err)
	form := <-forms
	assert.Equal(t, "authorization_code", form.Get("grant_type"))
	assert.Equal(t, ClientID, form.Get("client_id"))
	assert.Equal(t, "code-1", form.Get("code"))
	assert.Equal(t, "verifier-1", form.Get("code_verifier"))
	assert.Equal(t, "http://127.0.0.1:1/callback", form.Get("redirect_uri"))

	_, err = oauth.RefreshToken(t.Context(), "ort_old")
	require.NoError(t, err)
	form = <-forms
	assert.Equal(t, "refresh_token", form.Get("grant_type"))
	assert.Equal(t, "ort_old", form.Get("refresh_token"))

	_, err = oauth.PollDeviceAuthorization(t.Context(), "device-1")
	require.NoError(t, err)
	form = <-forms
	assert.Equal(t, GrantTypeDeviceCode, form.Get("grant_type"))
	assert.Equal(t, "device-1", form.Get("device_code"))
}

func TestOAuthErrorCarriesTheProtocolCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Request-ID", "device-request")
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"error":"authorization_pending","error_description":"the user has not approved the request yet"}`))
	}))
	t.Cleanup(server.Close)

	oauth := newOAuth(AuthorizationServerMetadata{TokenEndpoint: server.URL + "/oauth/token"}, "", server.Client())
	_, err := oauth.PollDeviceAuthorization(t.Context(), "device-1")
	var protocol *OAuthError
	require.ErrorAs(t, err, &protocol)
	require.Equal(t, "authorization_pending", protocol.Code)
	require.Equal(t, "the user has not approved the request yet", protocol.Description)
	require.Equal(t, "device-request", protocol.RequestID)
	require.False(t, protocol.Retryable)
}

func TestOAuthReportsUnavailableFlows(t *testing.T) {
	oauth := newOAuth(AuthorizationServerMetadata{Issuer: "https://control.example.com"}, "", http.DefaultClient)
	_, err := oauth.StartDeviceAuthorization(t.Context())
	require.ErrorContains(t, err, "does not offer device login")

	err = oauth.RevokeToken(t.Context(), "ort_old")
	require.ErrorContains(t, err, "does not offer token revocation")
	require.NoError(t, oauth.RevokeToken(t.Context(), ""))
}

func TestOAuthRevocationPostsTheToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.NoError(t, request.ParseForm())
		assert.Equal(t, "/oauth/revoke", request.URL.Path)
		assert.Equal(t, "ort_old", request.PostForm.Get("token"))
		assert.Equal(t, ClientID, request.PostForm.Get("client_id"))
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	oauth := newOAuth(AuthorizationServerMetadata{RevocationEndpoint: server.URL + "/oauth/revoke"}, "", server.Client())
	require.NoError(t, oauth.RevokeToken(t.Context(), "ort_old"))
	require.NoError(t, oauth.RevokeToken(t.Context(), ""))
}
