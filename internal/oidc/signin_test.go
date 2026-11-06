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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func environment(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestFromEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values map[string]string
		ok     bool
	}{
		{"empty environment", map[string]string{}, false},
		{"workspace only", map[string]string{"SCOPEDB_WORKSPACE_ID": "ws-1"}, true},
		{"token only", map[string]string{"SCOPEDB_OIDC_TOKEN": "jwt"}, true},
		{"token file only", map[string]string{"SCOPEDB_OIDC_TOKEN_FILE": "/tmp/token"}, true},
		{"all set", map[string]string{
			"SCOPEDB_WORKSPACE_ID":    "ws-1",
			"SCOPEDB_OIDC_TOKEN":      "jwt",
			"SCOPEDB_OIDC_TOKEN_FILE": "/tmp/token",
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signIn, ok := FromEnvironment(environment(tc.values))
			require.Equal(t, tc.ok, ok)
			if ok {
				require.Equal(t, strings.TrimSpace(tc.values["SCOPEDB_WORKSPACE_ID"]), signIn.WorkspaceID())
			}
		})
	}
}

func TestSignInToken(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("file.jwt.token\n"), 0o600))

	t.Run("literal token", func(t *testing.T) {
		signIn, ok := FromEnvironment(environment(map[string]string{"SCOPEDB_OIDC_TOKEN": "  env.jwt.token  "}))
		require.True(t, ok)
		token, err := signIn.Token()
		require.NoError(t, err)
		require.Equal(t, "env.jwt.token", token)
	})

	t.Run("token file", func(t *testing.T) {
		signIn, ok := FromEnvironment(environment(map[string]string{"SCOPEDB_OIDC_TOKEN_FILE": tokenFile}))
		require.True(t, ok)
		token, err := signIn.Token()
		require.NoError(t, err)
		require.Equal(t, "file.jwt.token", token)
	})

	t.Run("literal token wins over file", func(t *testing.T) {
		signIn, ok := FromEnvironment(environment(map[string]string{
			"SCOPEDB_OIDC_TOKEN":      "env.jwt.token",
			"SCOPEDB_OIDC_TOKEN_FILE": tokenFile,
		}))
		require.True(t, ok)
		token, err := signIn.Token()
		require.NoError(t, err)
		require.Equal(t, "env.jwt.token", token)
	})

	t.Run("no token source", func(t *testing.T) {
		signIn, ok := FromEnvironment(environment(map[string]string{"SCOPEDB_WORKSPACE_ID": "ws-1"}))
		require.True(t, ok)
		_, err := signIn.Token()
		require.ErrorIs(t, err, ErrNoToken)
	})

	t.Run("missing file", func(t *testing.T) {
		signIn, ok := FromEnvironment(environment(map[string]string{
			"SCOPEDB_OIDC_TOKEN_FILE": filepath.Join(t.TempDir(), "absent"),
		}))
		require.True(t, ok)
		_, err := signIn.Token()
		require.ErrorIs(t, err, ErrNoToken)
		require.NotContains(t, err.Error(), "file.jwt.token")
	})

	t.Run("empty file", func(t *testing.T) {
		empty := filepath.Join(t.TempDir(), "empty")
		require.NoError(t, os.WriteFile(empty, []byte(" \n"), 0o600))
		signIn, ok := FromEnvironment(environment(map[string]string{"SCOPEDB_OIDC_TOKEN_FILE": empty}))
		require.True(t, ok)
		_, err := signIn.Token()
		require.ErrorIs(t, err, ErrNoToken)
	})

	t.Run("oversized file", func(t *testing.T) {
		large := filepath.Join(t.TempDir(), "large")
		require.NoError(t, os.WriteFile(large, []byte(strings.Repeat("x", maxTokenBytes+2)), 0o600))
		signIn, ok := FromEnvironment(environment(map[string]string{"SCOPEDB_OIDC_TOKEN_FILE": large}))
		require.True(t, ok)
		_, err := signIn.Token()
		require.ErrorIs(t, err, ErrNoToken)
	})
}
