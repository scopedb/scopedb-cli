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

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	scopedb "github.com/scopedb/goscopedb"
	"github.com/scopedb/scopedb-cli/internal/auth"
)

type queryExecutorFunc func(context.Context, auth.Access, string) (*scopedb.ResultSet, error)

func (f queryExecutorFunc) Execute(ctx context.Context, access auth.Access, statement string) (*scopedb.ResultSet, error) {
	return f(ctx, access, statement)
}

func TestLoginThenStatusAgainstControlPlane(t *testing.T) {
	const sessionSecret = "session-super-secret"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case http.MethodPost + " /api/login":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode login body: %v", err)
			}
			if body["email"] != "dev@example.com" {
				t.Errorf("email = %q", body["email"])
			}
			_, _ = writer.Write([]byte(`{"login_challenge":"challenge-1"}`))
		case http.MethodPost + " /api/login/verify":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode verify body: %v", err)
			}
			if body["login_challenge"] != "challenge-1" || body["code"] != "123456" {
				t.Errorf("verify body = %#v", body)
			}
			_, _ = writer.Write([]byte(`{"token":"` + sessionSecret + `","workspace_id":"ws-1"}`))
		case http.MethodGet + " /api/session":
			if got, want := request.Header.Get("Authorization"), "Bearer "+sessionSecret; got != want {
				t.Errorf("Authorization = %q, want %q", got, want)
			}
			_, _ = writer.Write([]byte(`{"user":{"email":"dev@example.com","created_at":"2026-09-09T00:00:00Z"},"workspaces":[{"id":"ws-1","display_name":"Production","role":"owner"}],"current_workspace_id":"ws-1"}`))
		case http.MethodGet + " /api/workspaces/ws-1":
			_, _ = writer.Write([]byte(`{"workspace":{"id":"ws-1","display_name":"Production","role":"owner"},"connection":{"api_base_url":"https://data.example.com","auth_scheme":"api_key"},"placement":{"provider":"aws","region":"us-east-1"},"provisioning":{"status":"ready"}}`))
		default:
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_ENDPOINT", "")
	t.Setenv("SCOPEDB_API_KEY", "")
	t.Setenv("SCOPEDB_CONTROL_URL", "")
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")

	var loginOut, loginErr bytes.Buffer
	login := NewRootCommand(Dependencies{
		In:              strings.NewReader(""),
		Out:             &loginOut,
		ErrOut:          &loginErr,
		HTTPClient:      server.Client(),
		IsInputTerminal: func() bool { return false },
	})
	login.SetArgs([]string{"--control-url", server.URL, "login", "--email", "dev@example.com", "--code", "123456", "--insecure-storage"})
	if err := NormalizeError(login.ExecuteContext(context.Background())); err != nil {
		t.Fatalf("login error = %v", err)
	}
	if strings.Contains(loginOut.String(), sessionSecret) || strings.Contains(loginErr.String(), sessionSecret) {
		t.Fatal("login output exposed the session token")
	}
	if !strings.Contains(loginOut.String(), "Logged in as dev@example.com") {
		t.Errorf("login output = %q", loginOut.String())
	}

	var statusOut, statusErr bytes.Buffer
	status := NewRootCommand(Dependencies{
		In:              strings.NewReader(""),
		Out:             &statusOut,
		ErrOut:          &statusErr,
		HTTPClient:      server.Client(),
		IsInputTerminal: func() bool { return false },
	})
	status.SetArgs([]string{"status", "--format", "json"})
	if err := NormalizeError(status.ExecuteContext(context.Background())); err != nil {
		t.Fatalf("status error = %v; stderr = %s", err, statusErr.String())
	}
	var view statusView
	if err := json.Unmarshal(statusOut.Bytes(), &view); err != nil {
		t.Fatalf("decode status: %v; output = %s", err, statusOut.String())
	}
	if view.User != "dev@example.com" || view.WorkspaceID != "ws-1" || view.WorkspaceName != "Production" || view.ProvisioningState != "ready" {
		t.Errorf("status = %#v", view)
	}
	if strings.Contains(statusOut.String(), sessionSecret) {
		t.Fatal("status output exposed the session token")
	}
}

func TestQueryUsesMachineCredentialsAndPublicSDK(t *testing.T) {
	const apiKey = "machine-super-secret"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/statements" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if got, want := request.Header.Get("Authorization"), "Bearer "+apiKey; got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{
            "statement_id":"01989a4e-4ee2-7e63-87a5-65ac3b5161dc",
            "status":"finished",
            "created_at":"2026-09-09T00:00:00Z",
            "progress":{},
            "result_set":{
                "metadata":{"fields":[{"name":"ready","data_type":"u_int"}],"num_rows":1},
                "format":"json",
                "rows":[["1"]]
            }
        }`))
	}))
	defer server.Close()

	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_ENDPOINT", server.URL)
	t.Setenv("SCOPEDB_API_KEY", apiKey)
	var stdout, stderr bytes.Buffer
	command := NewRootCommand(Dependencies{
		In:              strings.NewReader(""),
		Out:             &stdout,
		ErrOut:          &stderr,
		HTTPClient:      server.Client(),
		IsInputTerminal: func() bool { return false },
	})
	command.SetArgs([]string{"query", "SELECT 1 AS ready", "--format", "json"})
	if err := NormalizeError(command.ExecuteContext(context.Background())); err != nil {
		t.Fatalf("query error = %v; stderr = %s", err, stderr.String())
	}
	want := "[\n  {\n    \"ready\": 1\n  }\n]\n"
	if got := stdout.String(); got != want {
		t.Errorf("query output:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(stdout.String(), apiKey) || strings.Contains(stderr.String(), apiKey) {
		t.Fatal("query output exposed the API key")
	}
}

func TestDoctorWithMachineCredentialsChecksDataPlaneOnly(t *testing.T) {
	const (
		apiKey   = "machine-super-secret"
		endpoint = "https://data.example.com"
	)
	var queryCalls atomic.Int64
	query := queryExecutorFunc(func(_ context.Context, access auth.Access, statement string) (*scopedb.ResultSet, error) {
		queryCalls.Add(1)
		if access.Endpoint != endpoint || access.APIKey != apiKey {
			t.Errorf("data-plane access = %#v", access)
		}
		if statement != doctorStatement {
			t.Errorf("statement = %q, want %q", statement, doctorStatement)
		}
		return &scopedb.ResultSet{}, nil
	})

	var controlRequests atomic.Int64
	controlServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		controlRequests.Add(1)
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer controlServer.Close()

	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_ENDPOINT", endpoint)
	t.Setenv("SCOPEDB_API_KEY", apiKey)
	t.Setenv("SCOPEDB_CONTROL_URL", "")
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")

	var stdout, stderr bytes.Buffer
	command := NewRootCommand(Dependencies{
		In:              strings.NewReader(""),
		Out:             &stdout,
		ErrOut:          &stderr,
		HTTPClient:      controlServer.Client(),
		QueryExecutor:   query,
		IsInputTerminal: func() bool { return false },
	})
	command.SetArgs([]string{"--control-url", controlServer.URL, "doctor", "--format", "json"})
	if err := NormalizeError(command.ExecuteContext(context.Background())); err != nil {
		t.Fatalf("doctor error = %v; output = %s; stderr = %s", err, stdout.String(), stderr.String())
	}

	var report doctorReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode doctor report: %v; output = %s", err, stdout.String())
	}
	checks := make(map[string]string, len(report.Checks))
	for _, check := range report.Checks {
		checks[check.Name] = check.Status
	}
	if !report.OK || checks["authentication"] != "pass" || checks["data plane"] != "pass" {
		t.Errorf("doctor report = %#v", report)
	}
	if _, exists := checks["control plane"]; exists {
		t.Errorf("machine-mode report unexpectedly checked the control plane: %#v", report)
	}
	if got := queryCalls.Load(); got != 1 {
		t.Errorf("data-plane queries = %d, want 1", got)
	}
	if got := controlRequests.Load(); got != 0 {
		t.Errorf("control-plane requests = %d, want 0", got)
	}
	if strings.Contains(stdout.String(), apiKey) || strings.Contains(stderr.String(), apiKey) {
		t.Fatal("doctor output exposed the API key")
	}
}
