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
	"fmt"
	keyring "github.com/zalando/go-keyring"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exercise independent grants through the OAuth and control-plane HTTP boundaries.
// The service rejects old rotated tokens and keeps revocation scoped to one grant.
func TestProfileGrantLifecycle(t *testing.T) {
	for _, sameAccount := range []bool{true, false} {
		t.Run(fmt.Sprintf("same_account_%t", sameAccount), func(t *testing.T) {
			fake, _ := setupCLITest(t)
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-dev", "Development"), workspaceFixture("ws-prod", "Production")}
			for _, ws := range fake.Workspaces {
				fake.Details[ws.ID] = controlplane.WorkspaceDetails{Workspace: ws}
			}
			type grant struct {
				access, refresh, user string
				rotations             int
				revoked               bool
			}
			var grants []*grant
			var mu sync.Mutex
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/token" {
					assert.NoError(t, r.ParseForm())
					mu.Lock()
					defer mu.Unlock()
					if r.Form.Get("grant_type") == controlplane.GrantTypeDeviceCode {
						i := len(grants) + 1
						user := "same-user"
						if !sameAccount {
							user = fmt.Sprintf("user-%d", i)
						}
						g := &grant{access: fmt.Sprintf("access-%d", i), refresh: fmt.Sprintf("refresh-%d", i), user: user}
						grants = append(grants, g)
						fake.writeJSON(w, 200, fake.tokenSet(g.access, g.refresh))
						return
					}
					for _, g := range grants {
						if !g.revoked && g.refresh == r.Form.Get("refresh_token") {
							g.rotations++
							g.access += "-rotated"
							g.refresh += "-rotated"
							fake.writeJSON(w, 200, fake.tokenSet(g.access, g.refresh))
							return
						}
					}
					fake.writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
					return
				}
				if r.URL.Path == "/oauth/revoke" {
					assert.NoError(t, r.ParseForm())
					mu.Lock()
					defer mu.Unlock()
					for _, g := range grants {
						if g.refresh == r.Form.Get("token") {
							g.revoked = true
						}
					}
					w.WriteHeader(200)
					return
				}
				if strings.HasPrefix(r.URL.Path, "/api/") {
					mu.Lock()
					user := ""
					for _, g := range grants {
						if !g.revoked && "Bearer "+g.access == r.Header.Get("Authorization") {
							user = g.user
						}
					}
					mu.Unlock()
					if user == "" {
						w.WriteHeader(401)
						return
					}
					if r.URL.Path == "/api/user" {
						fake.writeJSON(w, 200, controlplane.User{ID: user, Email: user + "@example.com", Status: "active"})
						return
					}
				}
				fake.serve(w, r)
			}))
			t.Cleanup(server.Close)
			fake.URL, fake.Issuer = server.URL, server.URL
			t.Setenv("SCOPEDB_CONTROL_URL", server.URL)
			for _, name := range []string{"dev", "prod"} {
				args := []string{"auth", "login", "--profile", name, "--use-device-code", "--no-browser", "--workspace", "ws-" + name}
				if name == "prod" {
					args = append(args, "--insecure-storage")
				}
				_, _, err := runCommand(t, args...)
				require.NoError(t, err)
			}
			paths, err := config.ResolvePaths()
			require.NoError(t, err)
			cfg, err := config.Read(paths)
			require.NoError(t, err)
			require.Equal(t, "dev", cfg.CurrentProfile)
			require.Len(t, cfg.Profiles, 2)
			dev := credential.NewKeyringStore(config.CredentialReference(paths, "dev"))
			prod := credential.NewPlaintextStore(paths.CredentialsFile, config.CredentialReference(paths, "prod"))
			devState, err := dev.Load(fake.URL)
			require.NoError(t, err)
			prodState, err := prod.Load(fake.URL)
			require.NoError(t, err)
			require.NotEqual(t, devState.RefreshToken, prodState.RefreshToken)
			require.NotEqual(t, devState.LoginID, prodState.LoginID)
			for _, name := range []string{"dev", "prod"} {
				out, _, err := runCommand(t, "--profile", name, "auth", "status", "--format", "json")
				require.NoError(t, err)
				var view statusView
				require.NoError(t, json.Unmarshal([]byte(out), &view))
				require.Equal(t, name, view.Profile)
				require.Equal(t, "ws-"+name, view.WorkspaceID)
				expectedUser := "same-user"
				if !sameAccount {
					expectedUser = "user-1"
					if name == "prod" {
						expectedUser = "user-2"
					}
				}
				require.Equal(t, expectedUser, view.UserID)
			}
			// Refresh only production; logging out development must not revoke it.
			prodState.AccessTokenExpiresAt = time.Now().Add(-time.Minute)
			require.NoError(t, prod.Save(fake.URL, prodState))
			_, _, err = runCommand(t, "--profile", "prod", "auth", "status")
			require.NoError(t, err)
			rotated, err := prod.Load(fake.URL)
			require.NoError(t, err)
			require.NotEqual(t, prodState.RefreshToken, rotated.RefreshToken)
			unchanged, err := dev.Load(fake.URL)
			require.NoError(t, err)
			require.Equal(t, devState.RefreshToken, unchanged.RefreshToken)
			_, _, err = runCommand(t, "--profile", "dev", "auth", "logout")
			require.NoError(t, err)
			_, _, err = runCommand(t, "--profile", "prod", "auth", "status")
			require.NoError(t, err)
			_, _, err = runCommand(t, "profile", "use", "prod")
			require.NoError(t, err)
			// Re-login retains the workspace binding and does not change the current profile.
			_, _, err = runCommand(t, "--profile", "dev", "auth", "login", "--use-device-code", "--no-browser")
			require.NoError(t, err)
			cfg, err = config.Read(paths)
			require.NoError(t, err)
			require.Equal(t, "prod", cfg.CurrentProfile)
			require.Equal(t, "ws-dev", cfg.Profiles["dev"].WorkspaceID)
			mu.Lock()
			defer mu.Unlock()
			require.Len(t, grants, 3)
			require.True(t, grants[0].revoked)
			require.False(t, grants[1].revoked)
			require.Equal(t, 1, grants[1].rotations)
		})
	}
}

func TestProfileSelectionPrecedenceAndLoggedOutDefault(t *testing.T) {
	fake, store := setupCLITest(t)
	saveStoredLogin(t, store, fake.URL, "")
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	require.NoError(t, config.SaveProfile(paths, "other", config.Profile{ControlURL: fake.URL, ConsoleURL: config.DefaultConsoleURL}, false))
	env := func(name string) string {
		if name == "SCOPEDB_PROFILE" {
			return "other"
		}
		return ""
	}
	_, _, err = runCommandWith(t, Dependencies{Getenv: env}, "auth", "status")
	require.ErrorIs(t, err, auth.ErrNotLoggedIn)
	_, _, err = runCommandWith(t, Dependencies{Getenv: env}, "--profile", "default", "auth", "status")
	require.NoError(t, err)
	out, _, err := runCommandWith(t, Dependencies{Getenv: env}, "profile", "list", "--format", "json")
	require.NoError(t, err)
	var items []profileListItem
	require.NoError(t, json.Unmarshal([]byte(out), &items))
	require.True(t, items[0].Current)
	require.False(t, items[0].Effective)
	require.False(t, items[1].Current)
	require.True(t, items[1].Effective)
	out, _, err = runCommand(t, "profile", "use", "other", "--format", "json")
	require.NoError(t, err)
	require.JSONEq(t, `{"name":"other","changed":true}`, out)
	_, _, err = runCommand(t, "auth", "status")
	require.ErrorIs(t, err, auth.ErrNotLoggedIn)
	_, _, err = runCommand(t, "--profile", "missing", "auth", "status")
	require.ErrorIs(t, err, config.ErrUnknownProfile)
	cfg, err := config.Read(paths)
	require.NoError(t, err)
	require.Equal(t, "other", cfg.CurrentProfile)
	_, _, err = runCommand(t, "--profile", "default", "--control-url", "https://different.example.com", "auth", "status")
	require.ErrorContains(t, err, "bound to")
}

func TestProfileMachineCredentialConflict(t *testing.T) {
	fake, store := setupCLITest(t)
	saveStoredLogin(t, store, fake.URL, "")
	for _, values := range []map[string]string{
		{"SCOPEDB_ENDPOINT": "https://data.example.com", "SCOPEDB_API_KEY": "test-key"},
		{"SCOPEDB_API_KEY": "test-key"},
	} {
		for _, args := range [][]string{{"auth", "status"}, {"doctor"}, {"query", "SELECT 1"}, {"catalog", "list", "databases"}} {
			out, _, err := runCommandWith(t, Dependencies{Getenv: func(key string) string { return values[key] }}, append([]string{"--profile", "default"}, args...)...)
			require.Error(t, err)
			require.Contains(t, out+err.Error(), "--profile conflicts")
		}
	}
	out, _, err := runCommandWith(t, Dependencies{Getenv: func(name string) string {
		switch name {
		case "SCOPEDB_PROFILE":
			return "default"
		case "SCOPEDB_ENDPOINT":
			return "https://data.example.com"
		case "SCOPEDB_API_KEY":
			return "test-key"
		}
		return ""
	}}, "auth", "status", "--format", "json")
	require.NoError(t, err)
	require.Contains(t, out, `"credential_source": "environment"`)
}

func TestWorkspacePickerUsesIDsAndCancellationPreservesSelection(t *testing.T) {
	for _, input := range []string{"2\n", "\n", ""} {
		t.Run(fmt.Sprintf("input_%q", input), func(t *testing.T) {
			fake, store := setupCLITest(t)
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Same"), workspaceFixture("ws-2", "Same"), workspaceFixture("ws-3", "")}
			saveStoredLogin(t, store, fake.URL, "ws-1")
			out, diagnostics, err := runCommandWith(t, Dependencies{In: strings.NewReader(input), IsInputTerminal: func() bool { return true }, IsErrorTerminal: func() bool { return true }}, "workspace", "use", "--format", "json")
			state, loadErr := store.Load(fake.URL)
			require.NoError(t, loadErr)
			require.Contains(t, diagnostics, "Same (ws-1)")
			require.Contains(t, diagnostics, "Same (ws-2)")
			require.Contains(t, diagnostics, "ws-3")
			if input == "2\n" {
				require.NoError(t, err)
				require.Equal(t, "ws-2", state.WorkspaceID)
				require.Contains(t, out, `"id": "ws-2"`)
			} else {
				require.ErrorContains(t, err, "cancelled")
				require.Equal(t, "ws-1", state.WorkspaceID)
				require.Empty(t, out)
			}
		})
	}
}

func TestCancelledLoginPickerRetainsLoginWithoutTarget(t *testing.T) {
	fake, store := setupCLITest(t)
	fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-1", "Same"), workspaceFixture("ws-2", "Same")}
	_, _, err := runInteractiveLogin(t, fake, "\n")
	require.ErrorContains(t, err, "login saved")
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Empty(t, state.WorkspaceID)
	_, _, err = runCommand(t, "workspace", "use")
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	out, _, err := runCommand(t, "__complete", "workspace", "use", "ws-")
	require.NoError(t, err)
	require.Contains(t, out, "ws-1\tSame")
	require.Contains(t, out, "ws-2\tSame")
}

func TestFirstNamedLoginMigratesLegacyIntoDefault(t *testing.T) {
	fake, _ := setupCLITest(t)
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	legacy := credential.NewPlaintextStore(paths.CredentialsFile, "")
	require.NoError(t, legacy.Save(fake.URL, credential.State{AccessToken: "legacy-access", RefreshToken: "legacy-refresh", AccessTokenExpiresAt: time.Now().Add(time.Hour), WorkspaceID: "ws-old"}))
	_, _, err = runCommand(t, "--profile", "new", "auth", "login", "--use-device-code", "--no-browser")
	require.NoError(t, err)
	cfg, err := config.Read(paths)
	require.NoError(t, err)
	require.Equal(t, "default", cfg.CurrentProfile)
	require.Len(t, cfg.Profiles, 2)
	require.Equal(t, "ws-old", cfg.Profiles["default"].WorkspaceID)
	migrated := credential.NewPlaintextStore(paths.CredentialsFile, config.CredentialReference(paths, "default"))
	state, err := migrated.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "legacy-refresh", state.RefreshToken)
	raw, err := os.ReadFile(paths.Config)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "legacy-refresh")
}

func TestLegacyVersionTwoMigratesWithBackendAndWorkspace(t *testing.T) {
	for _, backend := range []string{credential.SourceKeyring, credential.SourcePlaintext} {
		t.Run(backend, func(t *testing.T) {
			fake, _ := setupCLITest(t)
			paths, err := config.ResolvePaths()
			require.NoError(t, err)
			require.NoError(t, config.Save(paths, config.Config{ControlURL: fake.URL, ConsoleURL: config.DefaultConsoleURL}))
			state := credential.State{Version: 2, ControlURL: fake.URL, AccessToken: "old-access", RefreshToken: "old-refresh", AccessTokenExpiresAt: time.Now().Add(time.Hour), WorkspaceID: "ws-old"}
			raw, err := json.Marshal(state)
			require.NoError(t, err)
			if backend == credential.SourceKeyring {
				require.NoError(t, keyring.Set("io.scopedb.scope", profileKeyFor(fake.URL), string(raw)))
			} else {
				document := `{"version":1,"profiles":{"` + profileKeyFor(fake.URL) + `":` + string(raw) + `}}`
				require.NoError(t, os.WriteFile(paths.CredentialsFile, []byte(document), 0o600))
			}
			fake.Workspaces = []controlplane.Workspace{workspaceFixture("ws-old", "Existing")}
			fake.Details["ws-old"] = controlplane.WorkspaceDetails{Workspace: fake.Workspaces[0]}
			out, _, err := runCommand(t, "auth", "status", "--format", "json")
			require.NoError(t, err)
			var view statusView
			require.NoError(t, json.Unmarshal([]byte(out), &view))
			require.Equal(t, "default", view.Profile)
			require.Equal(t, "ws-old", view.WorkspaceID)
			require.Equal(t, backend, view.CredentialSource)
			cfg, err := config.Read(paths)
			require.NoError(t, err)
			require.Equal(t, "default", cfg.CurrentProfile)
			// A new directory cannot inherit the migrated keyring login.
			t.Setenv("SCOPEDB_HOME", filepath.Join(t.TempDir(), "fresh"))
			_, _, err = runCommand(t, "auth", "status")
			require.ErrorIs(t, err, auth.ErrNotLoggedIn)
		})
	}
}

func TestNamedProfileFailureHintsKeepTheSelectedProfile(t *testing.T) {
	fake, _ := setupCLITest(t)
	_, _, err := runCommand(t, "auth", "login", "--profile", "prod", "--use-device-code", "--no-browser")
	require.NoError(t, err)
	_, _, err = runCommand(t, "auth", "login", "--profile", "prod")
	require.Contains(t, clierror.Render(err), "scope --profile prod auth logout")
	_, _, err = runCommand(t, "--profile", "prod", "auth", "logout")
	require.NoError(t, err)
	_, _, err = runCommand(t, "--profile", "prod", "auth", "status")
	require.Contains(t, clierror.Render(err), `not logged in to profile "prod"`)
	require.Contains(t, clierror.Render(err), "scope --profile prod auth login")
	require.Equal(t, []string{fake.RefreshToken}, fake.RevokedTokens)
}

func TestLegacyMigrationRequiresSafeCleanupButMachineAccessRemainsAvailable(t *testing.T) {
	fake, _ := setupCLITest(t)
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	legacy := credential.NewPlaintextStore(paths.CredentialsFile, "")
	require.NoError(t, legacy.Save(fake.URL, credential.State{AccessToken: "old-access", RefreshToken: "old-refresh", AccessTokenExpiresAt: time.Now().Add(time.Hour)}))
	keyring.MockInitWithError(os.ErrPermission)
	_, _, err = runCommand(t, "auth", "status")
	require.ErrorIs(t, err, os.ErrPermission)
	require.Contains(t, clierror.Render(err), "restore OS keyring access and retry")
	require.NotContains(t, clierror.Render(err), "--insecure-storage")
	state, err := legacy.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, "old-refresh", state.RefreshToken)
	_, _, err = runCommandWith(t, Dependencies{Getenv: func(name string) string {
		switch name {
		case "SCOPEDB_ENDPOINT":
			return "https://data.example.com"
		case "SCOPEDB_API_KEY":
			return "test-key"
		}
		return ""
	}}, "auth", "status")
	require.NoError(t, err)
}
