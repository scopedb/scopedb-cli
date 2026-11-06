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
		want   bool
	}{
		{"empty environment", map[string]string{}, false},
		{"workspace only", map[string]string{"SCOPEDB_WORKSPACE_ID": "ws-1"}, false},
		{"blank token", map[string]string{"SCOPEDB_OIDC_TOKEN": "  "}, false},
		{"token only", map[string]string{"SCOPEDB_OIDC_TOKEN": "jwt"}, true},
		{"all set", map[string]string{
			"SCOPEDB_WORKSPACE_ID": "ws-1",
			"SCOPEDB_OIDC_TOKEN":   "jwt",
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signIn := FromEnvironment(environment(tc.values))
			require.Equal(t, tc.want, signIn != nil)
			if signIn != nil {
				require.Equal(t, strings.TrimSpace(tc.values["SCOPEDB_WORKSPACE_ID"]), signIn.WorkspaceID)
				require.Equal(t, strings.TrimSpace(tc.values["SCOPEDB_OIDC_TOKEN"]), signIn.Token)
			}
		})
	}
}
