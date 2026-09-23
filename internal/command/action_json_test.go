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
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionJSONResults(t *testing.T) {
	currentWorkspace := "ws-1"
	store, controlURL := setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/session":
			_, _ = w.Write([]byte(`{"user":{"email":"dev@example.com","status":"active"},"workspaces":[{"id":"ws-1","display_name":"Alpha"},{"id":"ws-2","display_name":"Beta"}],"current_workspace_id":"` + currentWorkspace + `"}`))
		case "POST /api/session/workspace":
			currentWorkspace = "ws-2"
			_, _ = w.Write([]byte(`{"token":"rotated-secret","workspace_id":"ws-2"}`))
		case "GET /api/workspaces/ws-2/api-keys":
			_, _ = w.Write([]byte(`[{"id":"key-1","name":"automation","tags":[],"status":"active","created_by":"dev@example.com","created_at":"2026-09-01T00:00:00Z","key":"returned-key-secret"}]`))
		case "DELETE /api/workspaces/ws-2/api-keys/automation":
			w.WriteHeader(http.StatusNoContent)
		case "DELETE /api/session":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	require.NoError(t, config.Save(paths, config.Config{
		ControlURL: controlURL, ConsoleURL: config.DefaultConsoleURL, CredentialStore: config.CredentialStorePlaintext,
	}))
	require.NoError(t, store.Save(controlURL, credential.State{SessionToken: "session-secret", WorkspaceID: "ws-1"}))

	out, diagnostics, err := runCommand(t, "workspace", "use", "ws-2", "--format", "json")
	require.NoError(t, err)
	require.Empty(t, diagnostics)
	var selected workspaceUseResult
	require.NoError(t, json.Unmarshal([]byte(out), &selected))
	require.Equal(t, "ws-2", selected.ID)
	require.Equal(t, "Beta", *selected.DisplayName)
	require.True(t, selected.Changed)

	out, _, err = runCommand(t, "workspace", "use", "ws-2", "--format", "json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(out), &selected))
	require.False(t, selected.Changed)

	out, _, err = runCommand(t, "api-key", "list", "--format", "json")
	require.NoError(t, err)
	var keys []map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &keys))
	require.Len(t, keys, 1)
	require.NotContains(t, keys[0], "key")
	require.NotContains(t, out, "returned-key-secret")

	out, _, err = runCommand(t, "api-key", "revoke", "automation", "--yes", "--format", "json")
	require.NoError(t, err)
	var revoked apiKeyRevokeResult
	require.NoError(t, json.Unmarshal([]byte(out), &revoked))
	require.Equal(t, apiKeyRevokeResult{Name: "automation", Revoked: true}, revoked)

	out, _, err = runCommand(t, "logout", "--format", "json")
	require.NoError(t, err)
	var loggedOut logoutResult
	require.NoError(t, json.Unmarshal([]byte(out), &loggedOut))
	require.True(t, loggedOut.LoggedOut)
	out, _, err = runCommand(t, "logout", "--format", "json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(out), &loggedOut))
	require.False(t, loggedOut.LoggedOut)
}

func TestRevokeJSONCancellationDoesNotCallService(t *testing.T) {
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In:              strings.NewReader("n\n"),
		Out:             &out,
		ErrOut:          &diagnostics,
		IsInputTerminal: func() bool { return true },
	})
	root.SetArgs([]string{"api-key", "revoke", "automation", "--format", "json"})
	require.NoError(t, root.ExecuteContext(t.Context()))
	var result apiKeyRevokeResult
	require.NoError(t, json.Unmarshal(out.Bytes(), &result))
	require.Equal(t, apiKeyRevokeResult{Name: "automation", Revoked: false}, result)
	require.Contains(t, diagnostics.String(), "Revoke API key")
}

func TestOpenAndVersionJSON(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	var out, diagnostics bytes.Buffer
	var opened string
	root := NewRoot(Dependencies{
		In:     strings.NewReader(""),
		Out:    &out,
		ErrOut: &diagnostics,
		OpenURL: func(target string) error {
			opened = target
			return nil
		},
	})
	root.SetArgs([]string{"open", "query", "--format", "json"})
	require.NoError(t, root.ExecuteContext(t.Context()))
	var result openResult
	require.NoError(t, json.Unmarshal(out.Bytes(), &result))
	require.Equal(t, "query", result.Page)
	require.Equal(t, opened, result.URL)
	require.True(t, result.Opened)
	require.Empty(t, diagnostics.String())

	out.Reset()
	root = NewRoot(Dependencies{In: strings.NewReader(""), Out: &out, ErrOut: &diagnostics})
	root.SetArgs([]string{"open", "keys", "--print", "--format", "json"})
	require.NoError(t, root.ExecuteContext(t.Context()))
	require.NoError(t, json.Unmarshal(out.Bytes(), &result))
	require.Equal(t, "keys", result.Page)
	require.False(t, result.Opened)

	out.Reset()
	root = NewRoot(Dependencies{In: strings.NewReader(""), Out: &out, ErrOut: &diagnostics})
	root.SetArgs([]string{"version", "--format", "json"})
	require.NoError(t, root.ExecuteContext(t.Context()))
	var version map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &version))
	require.NotEmpty(t, version["version"])

	out.Reset()
	root = NewRoot(Dependencies{In: strings.NewReader(""), Out: &out, ErrOut: &diagnostics})
	root.SetArgs([]string{"version", "--json", "--format", "text"})
	require.Error(t, root.ExecuteContext(t.Context()))
	require.Empty(t, out.String())
}

type blockConfigStore struct {
	credential.Store
	configPath string
}

func (s *blockConfigStore) Save(controlURL string, state credential.State) error {
	if err := s.Store.Save(controlURL, state); err != nil {
		return err
	}
	if state.SessionToken == "session-secret" {
		return os.Mkdir(s.configPath, 0o700)
	}
	return nil
}

type failAfterSaveStore struct {
	credential.Store
}

func (s *failAfterSaveStore) Save(controlURL string, state credential.State) error {
	if err := s.Store.Save(controlURL, state); err != nil {
		return err
	}
	if state.SessionToken == "session-secret" {
		return errors.New("simulated credential write failure")
	}
	return nil
}

func TestLoginRestoresCredentialsWhenCredentialSaveFails(t *testing.T) {
	var revoked atomic.Bool
	store, controlURL := setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/login":
			_, _ = w.Write([]byte(`{"login_challenge":"challenge-secret"}`))
		case "POST /api/login/verify":
			_, _ = w.Write([]byte(`{"token":"session-secret"}`))
		case "DELETE /api/session":
			revoked.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	require.NoError(t, store.Save(controlURL, credential.State{SessionToken: "prior-secret"}))
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In: strings.NewReader(""), Out: &out, ErrOut: &diagnostics,
		CredentialStore: func(string, config.Paths) (credential.Store, error) {
			return &failAfterSaveStore{Store: store}, nil
		},
	})
	root.SetArgs([]string{"login", "--email", "dev@example.com", "--code", "123456", "--format", "json"})
	require.ErrorContains(t, root.ExecuteContext(t.Context()), "credentials could not be stored")
	require.Empty(t, out.String())
	state, err := store.Load(controlURL)
	require.NoError(t, err)
	require.Equal(t, "prior-secret", state.SessionToken)
	assert.True(t, revoked.Load())
}

func TestLoginRestoresCredentialsWhenConfigSaveFails(t *testing.T) {
	var revoked atomic.Bool
	store, controlURL := setupLoginTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/login":
			_, _ = w.Write([]byte(`{"login_challenge":"challenge-secret"}`))
		case "POST /api/login/verify":
			_, _ = w.Write([]byte(`{"token":"session-secret"}`))
		case "DELETE /api/session":
			revoked.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	require.NoError(t, store.Save(controlURL, credential.State{SessionToken: "prior-secret"}))
	blocking := &blockConfigStore{Store: store, configPath: paths.Config}
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In: strings.NewReader(""), Out: &out, ErrOut: &diagnostics,
		CredentialStore: func(string, config.Paths) (credential.Store, error) { return blocking, nil },
	})
	root.SetArgs([]string{"login", "--email", "dev@example.com", "--code", "123456", "--format", "json"})
	require.ErrorContains(t, root.ExecuteContext(t.Context()), "configuration could not be stored")
	require.Empty(t, out.String())
	state, err := store.Load(controlURL)
	require.NoError(t, err)
	require.Equal(t, "prior-secret", state.SessionToken)
	assert.True(t, revoked.Load())
	_, err = os.Stat(filepath.Join(paths.Directory, "config.toml"))
	require.NoError(t, err)
}
