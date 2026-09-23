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
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginThroughApprovalAndWorkspaceSelection(t *testing.T) {
	var session atomic.Value
	session.Store(controlplane.Session{
		User:       controlplane.User{Email: "dev@example.com", Status: "pending"},
		Workspaces: []controlplane.Workspace{},
	})
	var revoked atomic.Int32
	store, controlURL := setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		current := session.Load().(controlplane.Session)
		if strings.HasPrefix(r.URL.Path, "/api/session") || strings.HasPrefix(r.URL.Path, "/api/workspaces") {
			token := "session-secret"
			if current.CurrentWorkspaceID != "" {
				token = "rotated-secret"
			}
			assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /api/login":
			_, _ = w.Write([]byte(`{"login_challenge":"challenge-secret"}`))
		case "POST /api/login/verify":
			_, _ = w.Write([]byte(`{"token":"session-secret"}`))
		case "GET /api/session":
			assert.NoError(t, json.NewEncoder(w).Encode(current))
		case "GET /healthz":
			w.WriteHeader(http.StatusOK)
		case "POST /api/session/workspace":
			var body map[string]string
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, "ws-1", body["workspace_id"])
			current.CurrentWorkspaceID = "ws-1"
			session.Store(current)
			_, _ = w.Write([]byte(`{"token":"rotated-secret","workspace_id":"ws-1"}`))
		case "GET /api/workspaces/ws-1":
			_, _ = w.Write([]byte(`{"workspace":{"id":"ws-1","display_name":"Analytics"},"connection":{"api_base_url":"https://data.example.com","auth_scheme":"Bearer"},"placement":{"provider":"aws","region":"us-east-1"},"provisioning":{"status":"ready","updated_at":"2026-09-15T00:00:00Z"}}`))
		case "DELETE /api/session":
			revoked.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))

	out, diagnostics, err := runCommand(t, "login", "--email", "dev@example.com", "--code", "123456", "--insecure-storage", "--format", "json")
	require.NoError(t, err)
	var login loginResult
	require.NoError(t, json.Unmarshal([]byte(out), &login))
	require.Equal(t, "dev@example.com", login.Email)
	require.Nil(t, login.WorkspaceID)
	require.Contains(t, diagnostics, "awaiting approval")
	state, err := store.Load(controlURL)
	require.NoError(t, err)
	require.Equal(t, "session-secret", state.SessionToken)
	require.Empty(t, state.WorkspaceID)
	require.Zero(t, revoked.Load())

	for _, phase := range []struct {
		name       string
		status     string
		workspaces []controlplane.Workspace
		message    string
		hint       string
		exitCode   int
	}{
		{"pending", "pending", nil, "awaiting approval", "scope open", clierror.ExitAuth},
		{"approved", "active", nil, "no workspaces", "create your first workspace", clierror.ExitUsage},
		{"created", "active", []controlplane.Workspace{{ID: "ws-1", DisplayName: new("Analytics")}}, "no workspace is selected", "scope workspace use", clierror.ExitUsage},
	} {
		t.Run(phase.name, func(t *testing.T) {
			session.Store(controlplane.Session{
				User:       controlplane.User{Email: "dev@example.com", Status: phase.status},
				Workspaces: phase.workspaces,
			})
			out, diagnostics, err := runCommand(t, "status", "--format", "json")
			require.NoError(t, err)
			var status map[string]any
			require.NoError(t, json.Unmarshal([]byte(out), &status))
			require.Equal(t, "dev@example.com", status["user"])
			require.Equal(t, phase.status, status["user_status"])
			require.NotContains(t, status, "workspace_id")
			require.Contains(t, diagnostics, phase.message)
			require.Contains(t, diagnostics, phase.hint)

			out, _, err = runCommand(t, "workspace", "list", "--format", "json")
			require.NoError(t, err)
			var workspaces []workspaceListItem
			require.NoError(t, json.Unmarshal([]byte(out), &workspaces))
			require.NotNil(t, workspaces)
			require.Len(t, workspaces, len(phase.workspaces))

			out, _, err = runCommand(t, "doctor", "--format", "json")
			require.NoError(t, err)
			var report doctorReport
			require.NoError(t, json.Unmarshal([]byte(out), &report))
			require.True(t, report.OK)
			require.Contains(t, report.Checks, doctorCheck{Name: "authentication", Status: "pass", Details: "dev@example.com"})
			require.Contains(t, out, phase.message)

			for _, args := range [][]string{
				{"workspace", "show"},
				{"query", "SELECT 1 AS ready"},
				{"api-key", "list"},
				{"api-key", "create", "automation"},
				{"api-key", "revoke", "automation", "--yes"},
			} {
				out, _, err := runCommand(t, args...)
				require.Equal(t, phase.exitCode, clierror.ExitCode(err), "%v: %v", args, err)
				require.Empty(t, out)
				require.Contains(t, clierror.Render(err), phase.hint)
			}
		})
	}

	out, _, err = runCommand(t, "workspace", "use", "Analytics")
	require.NoError(t, err)
	require.Contains(t, out, "Now using workspace Analytics (ws-1)")
	state, err = store.Load(controlURL)
	require.NoError(t, err)
	require.Equal(t, "rotated-secret", state.SessionToken)
	require.Equal(t, "ws-1", state.WorkspaceID)

	out, diagnostics, err = runCommand(t, "status", "--format", "json")
	require.NoError(t, err)
	require.Empty(t, diagnostics)
	var status statusView
	require.NoError(t, json.Unmarshal([]byte(out), &status))
	require.Equal(t, "ws-1", status.WorkspaceID)
	require.Equal(t, "Analytics", status.WorkspaceName)
	require.Equal(t, "ready", status.ProvisioningState)

	_, _, err = runCommand(t, "logout")
	require.NoError(t, err)
	require.EqualValues(t, 1, revoked.Load())
	_, err = store.Load(controlURL)
	require.ErrorIs(t, err, credential.ErrNotFound)
}

func TestLoginKeepsSessionWhenStatusLookupFails(t *testing.T) {
	var revoked atomic.Bool
	store, controlURL := setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/login":
			_, _ = w.Write([]byte(`{"login_challenge":"challenge-secret"}`))
		case "POST /api/login/verify":
			_, _ = w.Write([]byte(`{"token":"session-secret"}`))
		case "GET /api/session":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"message":"temporarily unavailable"}`))
		case "DELETE /api/session":
			revoked.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	out, diagnostics, err := runCommand(t, "login", "--email", "dev@example.com", "--code", "123456", "--insecure-storage")
	require.NoError(t, err)
	require.Contains(t, out, "Logged in as dev@example.com.")
	require.Contains(t, diagnostics, "scope status")
	state, err := store.Load(controlURL)
	require.NoError(t, err)
	require.Equal(t, "session-secret", state.SessionToken)
	require.False(t, revoked.Load())

	_, _, err = runCommand(t, "logout")
	require.NoError(t, err)
	require.True(t, revoked.Load())
	_, err = store.Load(controlURL)
	require.ErrorIs(t, err, credential.ErrNotFound)
}

func setupLoginTest(t *testing.T, handler http.Handler) (*credential.PlaintextStore, string) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_CONTROL_URL", server.URL)
	t.Setenv("SCOPEDB_CONSOLE_URL", "")
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	return credential.NewPlaintextStore(paths.CredentialsFile), server.URL
}

func TestFailedLoginDoesNotChangeConfig(t *testing.T) {
	_, controlURL := setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/login":
			_, _ = w.Write([]byte(`{"login_challenge":"challenge-secret"}`))
		case "/api/login/verify":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"invalid code"}`))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	require.NoError(t, config.Save(paths, config.Config{
		ControlURL:      "https://old.example.com",
		ConsoleURL:      config.DefaultConsoleURL,
		CredentialStore: config.CredentialStorePlaintext,
	}))
	before, err := os.ReadFile(paths.Config)
	require.NoError(t, err)
	out, _, err := runCommand(t, "--control-url", controlURL, "login", "--email", "dev@example.com", "--code", "bad-code", "--format", "json")
	require.Error(t, err)
	require.Empty(t, out)
	after, err := os.ReadFile(paths.Config)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestLoginReadsVerificationCodeFromStdin(t *testing.T) {
	_, _ = setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/login":
			_, _ = w.Write([]byte(`{"login_challenge":"challenge-secret"}`))
		case "/api/login/verify":
			var request map[string]string
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			assert.Equal(t, "123456", request["code"])
			_, _ = w.Write([]byte(`{"token":"session-secret","workspace_id":"ws-1"}`))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{In: strings.NewReader("123456\n"), Out: &out, ErrOut: &diagnostics})
	root.SetArgs([]string{"login", "--email", "dev@example.com", "--insecure-storage", "--format", "json"})
	require.NoError(t, root.ExecuteContext(t.Context()))
	var result loginResult
	require.NoError(t, json.Unmarshal(out.Bytes(), &result))
	require.Equal(t, "dev@example.com", result.Email)
	require.Equal(t, "ws-1", *result.WorkspaceID)
	require.NotContains(t, out.String()+diagnostics.String(), "123456")
	require.NotContains(t, out.String()+diagnostics.String(), "session-secret")
}

func runCommand(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In:     strings.NewReader(""),
		Out:    &out,
		ErrOut: &diagnostics,
		Getenv: func(string) string { return "" },
	})
	root.SetArgs(args)
	err := root.ExecuteContext(t.Context())
	for _, secret := range []string{"session-secret", "rotated-secret", "challenge-secret", "123456"} {
		require.NotContains(t, out.String()+diagnostics.String(), secret)
	}
	return out.String(), diagnostics.String(), err
}
