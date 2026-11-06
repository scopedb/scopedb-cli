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
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// envWorkspaceID selects the workspace an unattended run authenticates to.
	envWorkspaceID = "SCOPEDB_WORKSPACE_ID"
	// envToken carries an OIDC token issued by the CI environment's provider;
	// envTokenFile points at a file holding one. Provider-specific token
	// requests happen outside the CLI: GitHub Actions jobs use the
	// scopedb/actions-login action, other CI systems export their provider's
	// token directly.
	envToken     = "SCOPEDB_OIDC_TOKEN"
	envTokenFile = "SCOPEDB_OIDC_TOKEN_FILE"

	maxTokenBytes = 64 << 10
)

// ErrNoToken reports that the environment cannot provide an OIDC token.
var ErrNoToken = errors.New("the environment did not provide an OIDC token")

// SignIn is an unattended CI sign-in resolved from the environment: a
// workspace target plus a provider-issued OIDC token.
type SignIn struct {
	workspaceID string
	token       string
	tokenFile   string
}

// FromEnvironment returns a SignIn when the environment asks for OIDC
// exchange: a workspace target or a token source is set. ok is false in
// ordinary interactive environments, where data commands should keep
// requiring a stored login.
func FromEnvironment(getenv func(string) string) (*SignIn, bool) {
	signIn := &SignIn{
		workspaceID: strings.TrimSpace(getenv(envWorkspaceID)),
		token:       strings.TrimSpace(getenv(envToken)),
		tokenFile:   strings.TrimSpace(getenv(envTokenFile)),
	}
	if signIn.workspaceID == "" && signIn.token == "" && signIn.tokenFile == "" {
		return nil, false
	}
	return signIn, true
}

// WorkspaceID returns the configured exchange target; empty means unset.
func (s *SignIn) WorkspaceID() string { return s.workspaceID }

// Token returns the provider-issued OIDC token: SCOPEDB_OIDC_TOKEN when set,
// otherwise the contents of the SCOPEDB_OIDC_TOKEN_FILE. The token is used
// once, for the credential exchange, and is never stored.
func (s *SignIn) Token() (string, error) {
	if s.token != "" {
		return s.token, nil
	}
	if s.tokenFile == "" {
		return "", ErrNoToken
	}
	file, err := os.Open(s.tokenFile)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrNoToken, err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxTokenBytes+1))
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrNoToken, err)
	}
	if len(data) > maxTokenBytes {
		return "", fmt.Errorf("%w: the token file is too large", ErrNoToken)
	}
	if token := strings.TrimSpace(string(data)); token != "" {
		return token, nil
	}
	return "", fmt.Errorf("%w: %s contains no token", ErrNoToken, s.tokenFile)
}
