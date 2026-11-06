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

// Package oidc reads CI-issued OIDC tokens for unattended data-plane access.
package oidc

import (
	"strings"
)

const (
	envWorkspaceID = "SCOPEDB_WORKSPACE_ID"
	// envToken carries an OIDC token issued by the CI environment's provider.
	// Provider-specific token requests happen outside the CLI: GitHub Actions
	// jobs use the scopedb/login-action action, other CI systems export their
	// provider's token directly.
	envToken = "SCOPEDB_OIDC_TOKEN"
)

// SignIn is an unattended CI sign-in: a workspace target plus a
// provider-issued OIDC token. The token is used once, for the credential
// exchange, and is never stored.
type SignIn struct {
	WorkspaceID string
	Token       string
}

// FromEnvironment returns the CI sign-in the environment configures, or nil
// in ordinary interactive environments, where data commands should keep
// requiring a stored login. Both the workspace target and the token must be
// set: either one alone is a misconfiguration the login flow cannot use.
func FromEnvironment(getenv func(string) string) *SignIn {
	workspaceID := strings.TrimSpace(getenv(envWorkspaceID))
	token := strings.TrimSpace(getenv(envToken))
	if workspaceID == "" || token == "" {
		return nil
	}
	return &SignIn{WorkspaceID: workspaceID, Token: token}
}
