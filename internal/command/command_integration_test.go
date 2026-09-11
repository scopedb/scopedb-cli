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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	scopedb "github.com/scopedb/goscopedb"
	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			assert.NoError(t, json.NewDecoder(request.Body).Decode(&body))
			assert.Equal(t, "dev@example.com", body["email"])
			_, _ = writer.Write([]byte(`{"login_challenge":"challenge-1"}`))
		case http.MethodPost + " /api/login/verify":
			var body map[string]string
			assert.NoError(t, json.NewDecoder(request.Body).Decode(&body))
			assert.Equal(t, map[string]string{"login_challenge": "challenge-1", "code": "123456"}, body)
			_, _ = writer.Write([]byte(`{"token":"` + sessionSecret + `","workspace_id":"ws-1"}`))
		case http.MethodGet + " /api/session":
			assert.Equal(t, "Bearer "+sessionSecret, request.Header.Get("Authorization"))
			_, _ = writer.Write([]byte(`{"user":{"email":"dev@example.com","created_at":"2026-09-09T00:00:00Z"},"workspaces":[{"id":"ws-1","display_name":"Production","role":"owner"}],"current_workspace_id":"ws-1"}`))
		case http.MethodGet + " /api/workspaces/ws-1":
			_, _ = writer.Write([]byte(`{"workspace":{"id":"ws-1","display_name":"Production","role":"owner"},"connection":{"api_base_url":"https://data.example.com","auth_scheme":"api_key"},"placement":{"provider":"aws","region":"us-east-1"},"provisioning":{"status":"ready"}}`))
		default:
			assert.Failf(t, "unexpected request", "%s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_ENDPOINT", "")
	t.Setenv("SCOPEDB_API_KEY", "")
	t.Setenv("SCOPEDB_CONTROL_URL", "")
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")

	var loginOut, loginErr bytes.Buffer
	login := NewRoot(Dependencies{
		In:              strings.NewReader(""),
		Out:             &loginOut,
		ErrOut:          &loginErr,
		HTTPClient:      server.Client(),
		IsInputTerminal: func() bool { return false },
	})
	login.SetArgs([]string{"--control-url", server.URL, "login", "--email", "dev@example.com", "--code", "123456", "--insecure-storage"})
	require.NoError(t, NormalizeError(login.ExecuteContext(t.Context())))
	require.NotContains(t, loginOut.String(), sessionSecret)
	require.NotContains(t, loginErr.String(), sessionSecret)
	require.Contains(t, loginOut.String(), "Logged in as dev@example.com")

	var statusOut, statusErr bytes.Buffer
	status := NewRoot(Dependencies{
		In:              strings.NewReader(""),
		Out:             &statusOut,
		ErrOut:          &statusErr,
		HTTPClient:      server.Client(),
		IsInputTerminal: func() bool { return false },
	})
	status.SetArgs([]string{"status", "--format", "json"})
	require.NoError(t, NormalizeError(status.ExecuteContext(t.Context())), "stderr: %s", statusErr.String())
	var view statusView
	require.NoError(t, json.Unmarshal(statusOut.Bytes(), &view), "output: %s", statusOut.String())
	require.Equal(t, "dev@example.com", view.User)
	require.Equal(t, "ws-1", view.WorkspaceID)
	require.Equal(t, "Production", view.WorkspaceName)
	require.Equal(t, "ready", view.ProvisioningState)
	require.NotContains(t, statusOut.String(), sessionSecret)
}

func TestQueryUsesMachineCredentialsAndPublicSDK(t *testing.T) {
	const apiKey = "machine-super-secret"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, http.MethodPost, request.Method)
		assert.Equal(t, "/v1/statements", request.URL.Path)
		assert.Equal(t, "Bearer "+apiKey, request.Header.Get("Authorization"))
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
	t.Cleanup(server.Close)

	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_ENDPOINT", server.URL)
	t.Setenv("SCOPEDB_API_KEY", apiKey)
	var stdout, stderr bytes.Buffer
	command := NewRoot(Dependencies{
		In:              strings.NewReader(""),
		Out:             &stdout,
		ErrOut:          &stderr,
		HTTPClient:      server.Client(),
		IsInputTerminal: func() bool { return false },
	})
	command.SetArgs([]string{"query", "SELECT 1 AS ready", "--format", "json"})
	require.NoError(t, NormalizeError(command.ExecuteContext(t.Context())), "stderr: %s", stderr.String())
	want := "[\n  {\n    \"ready\": 1\n  }\n]\n"
	require.Equal(t, want, stdout.String())
	require.NotContains(t, stdout.String(), apiKey)
	require.NotContains(t, stderr.String(), apiKey)
}

func TestDoctorWithMachineCredentialsChecksDataPlaneOnly(t *testing.T) {
	const (
		apiKey   = "machine-super-secret"
		endpoint = "https://data.example.com"
	)
	var queryCalls atomic.Int64
	query := queryExecutorFunc(func(_ context.Context, access auth.Access, statement string) (*scopedb.ResultSet, error) {
		queryCalls.Add(1)
		require.Equal(t, endpoint, access.Endpoint)
		require.Equal(t, apiKey, access.APIKey)
		require.Equal(t, doctorStatement, statement)
		return &scopedb.ResultSet{}, nil
	})

	var controlRequests atomic.Int64
	controlServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		controlRequests.Add(1)
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(controlServer.Close)

	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_ENDPOINT", endpoint)
	t.Setenv("SCOPEDB_API_KEY", apiKey)
	t.Setenv("SCOPEDB_CONTROL_URL", "")
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")

	var stdout, stderr bytes.Buffer
	command := NewRoot(Dependencies{
		In:              strings.NewReader(""),
		Out:             &stdout,
		ErrOut:          &stderr,
		HTTPClient:      controlServer.Client(),
		QueryExecutor:   query,
		IsInputTerminal: func() bool { return false },
	})
	command.SetArgs([]string{"--control-url", controlServer.URL, "doctor", "--format", "json"})
	require.NoError(t, NormalizeError(command.ExecuteContext(t.Context())), "output: %s; stderr: %s", stdout.String(), stderr.String())

	var report doctorReport
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &report), "output: %s", stdout.String())
	checks := make(map[string]string, len(report.Checks))
	for _, check := range report.Checks {
		checks[check.Name] = check.Status
	}
	require.True(t, report.OK)
	require.Equal(t, "pass", checks["authentication"])
	require.Equal(t, "pass", checks["data plane"])
	require.NotContains(t, checks, "control plane")
	require.EqualValues(t, 1, queryCalls.Load())
	require.Zero(t, controlRequests.Load())
	require.NotContains(t, stdout.String(), apiKey)
	require.NotContains(t, stderr.String(), apiKey)
}
