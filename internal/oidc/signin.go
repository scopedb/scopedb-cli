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
	"errors"
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

// ErrNoToken reports that the environment cannot provide an OIDC token.
var ErrNoToken = errors.New("the environment did not provide an OIDC token")

// SignIn is an unattended CI sign-in resolved from the environment: a
// workspace target plus a provider-issued OIDC token.
type SignIn struct {
	workspaceID string
	token       string
}

// FromEnvironment returns a SignIn when the environment asks for OIDC
// exchange: a workspace target or a token is set. ok is false in ordinary
// interactive environments, where data commands should keep requiring a
// stored login.
func FromEnvironment(getenv func(string) string) (*SignIn, bool) {
	signIn := &SignIn{
		workspaceID: strings.TrimSpace(getenv(envWorkspaceID)),
		token:       strings.TrimSpace(getenv(envToken)),
	}
	if signIn.workspaceID == "" && signIn.token == "" {
		return nil, false
	}
	return signIn, true
}

// WorkspaceID returns the configured exchange target; empty means unset.
func (s *SignIn) WorkspaceID() string { return s.workspaceID }

// Token returns the provider-issued OIDC token. The token is used once, for
// the credential exchange, and is never stored.
func (s *SignIn) Token() (string, error) {
	if s.token == "" {
		return "", ErrNoToken
	}
	return s.token, nil
}
