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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientSessionRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/session" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if got, want := request.Header.Get("Authorization"), "Bearer session-secret"; got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
		if got, want := request.Header.Get("User-Agent"), "scope/test"; got != want {
			t.Errorf("User-Agent = %q, want %q", got, want)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"user":{"email":"dev@example.com","created_at":"2026-09-09T00:00:00Z"},"workspaces":[{"id":"ws-1","display_name":"Production","role":"owner"}],"current_workspace_id":"ws-1"}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "scope/test", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.GetSession(context.Background(), "session-secret")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if session.User.Email != "dev@example.com" || session.CurrentWorkspaceID != "ws-1" || len(session.Workspaces) != 1 {
		t.Errorf("GetSession() = %#v", session)
	}
}

func TestClientSendsLoginVerificationContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if body["login_challenge"] != "challenge-1" || body["code"] != "123456" {
			t.Errorf("body = %#v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"token":"session-secret","workspace_id":"ws-1"}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.VerifyLogin(context.Background(), "challenge-1", "123456")
	if err != nil {
		t.Fatalf("VerifyLogin() error = %v", err)
	}
	if response.Token != "session-secret" || response.WorkspaceID != "ws-1" {
		t.Errorf("VerifyLogin() = %#v", response)
	}
}

func TestClientPreservesStructuredHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Retry-After", "7")
		writer.Header().Set("X-Request-ID", "header-request")
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = writer.Write([]byte(`{"message":"slow down","request_id":"body-request"}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	err = client.Health(context.Background())
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("Health() error = %T %v, want *Error", err, err)
	}
	if apiErr.Status != http.StatusTooManyRequests || apiErr.Message != "slow down" || apiErr.RequestID != "body-request" || !apiErr.Retryable || apiErr.RetryAfter != 7*time.Second {
		t.Errorf("error = %#v", apiErr)
	}
}

func TestClientEscapesWorkspacePath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got, want := request.URL.EscapedPath(), "/api/workspaces/a%20workspace"; got != want {
			t.Errorf("EscapedPath() = %q, want %q", got, want)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"workspace":{"id":"a workspace","role":"owner"},"connection":{},"placement":{},"provisioning":{"status":"pending"}}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetWorkspace(context.Background(), "token", "a workspace"); err != nil {
		t.Fatalf("GetWorkspace() error = %v", err)
	}
}
