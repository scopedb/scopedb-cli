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

// Package oidc obtains CI-issued OIDC tokens for unattended data-plane access.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// envWorkspaceID selects the workspace an unattended run authenticates to.
	envWorkspaceID = "SCOPEDB_WORKSPACE_ID"
	// GitHub Actions exposes its OIDC token endpoint through these variables
	// when the job grants "permissions: id-token: write".
	envActionsRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	envActionsRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"

	maxTokenResponseBytes = 64 << 10
	tokenRequestTimeout   = 15 * time.Second
)

// ErrNoToken reports that the environment cannot issue an OIDC token.
var ErrNoToken = errors.New("the environment did not issue an OIDC token")

// SignIn is an unattended CI sign-in resolved from the environment: a
// workspace target plus the provider's OIDC token request.
type SignIn struct {
	workspaceID  string
	requestURL   string
	requestToken string
	http         *http.Client
}

// FromEnvironment returns a SignIn when the environment asks for OIDC
// exchange: a workspace target or a GitHub Actions token request is set. ok is
// false in ordinary interactive environments, where data commands should keep
// requiring a stored login.
func FromEnvironment(getenv func(string) string, httpClient *http.Client) (*SignIn, bool) {
	signIn := &SignIn{
		workspaceID:  strings.TrimSpace(getenv(envWorkspaceID)),
		requestURL:   strings.TrimSpace(getenv(envActionsRequestURL)),
		requestToken: strings.TrimSpace(getenv(envActionsRequestToken)),
		http:         httpClient,
	}
	if signIn.workspaceID == "" && signIn.requestURL == "" && signIn.requestToken == "" {
		return nil, false
	}
	return signIn, true
}

// WorkspaceID returns the configured exchange target; empty means unset.
func (s *SignIn) WorkspaceID() string { return s.workspaceID }

// Token fetches a GitHub Actions OIDC token for the audience. The token is
// used once, for the credential exchange, and is never stored.
func (s *SignIn) Token(ctx context.Context, audience string) (string, error) {
	switch {
	case s.requestURL == "" && s.requestToken == "":
		return "", ErrNoToken
	case s.requestURL == "" || s.requestToken == "":
		return "", fmt.Errorf("%w: GitHub Actions set only one of %s and %s",
			ErrNoToken, envActionsRequestURL, envActionsRequestToken)
	}
	target, err := url.Parse(s.requestURL)
	if err != nil || target.Host == "" {
		return "", fmt.Errorf("%s is not a valid URL", envActionsRequestURL)
	}
	switch target.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(target.Hostname()) {
			return "", fmt.Errorf("%s must use HTTPS", envActionsRequestURL)
		}
	default:
		return "", fmt.Errorf("%s is not a valid URL", envActionsRequestURL)
	}
	query := target.Query()
	query.Set("audience", audience)
	target.RawQuery = query.Encode()

	client := s.http
	if client == nil {
		client = &http.Client{Timeout: tokenRequestTimeout}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return "", fmt.Errorf("create GitHub Actions OIDC request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+s.requestToken)

	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", err
		}
		return "", fmt.Errorf("request a GitHub Actions OIDC token: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxTokenResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("read the GitHub Actions OIDC response: %w", err)
	}
	var payload struct {
		Value   string `json:"value"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(data, &payload)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if message := strings.TrimSpace(payload.Message); message != "" {
			return "", fmt.Errorf("GitHub Actions did not issue an OIDC token: %s", message)
		}
		return "", fmt.Errorf("GitHub Actions did not issue an OIDC token: %s", response.Status)
	}
	if int64(len(data)) > maxTokenResponseBytes {
		return "", errors.New("the GitHub Actions OIDC response is too large")
	}
	if payload.Value == "" {
		return "", errors.New("the GitHub Actions OIDC response contained no token")
	}
	return payload.Value, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
