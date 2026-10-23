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

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	ClientID            = "scopedb-cli"
	ScopePlatform       = "platform"
	GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

	metadataPath = "/.well-known/oauth-authorization-server"
)

type AuthorizationServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	DeviceAuthorizationEndpoint                string   `json:"device_authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

// TokenSet is one successful token response. RefreshTokenExpiresIn is the non-standard companion to
// expires_in that reports how long the refresh token stays usable.
type TokenSet struct {
	AccessToken           string `json:"access_token"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
	Scope                 string `json:"scope"`
}

type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

type OAuthError struct {
	Code        string
	Description string
	Status      int
	RequestID   string
	Retryable   bool
	RetryAfter  time.Duration
	Err         error
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return e.Description
	}
	if e.Code != "" {
		return e.Code
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "OAuth request failed"
}

func (e *OAuthError) Unwrap() error { return e.Err }

// OAuth talks to the authorization server discovered for one Control Plane origin. Its API endpoints
// are validated against the issuer before use, so a metadata document cannot redirect
// credentials or authorization codes somewhere else.
type OAuth struct {
	metadata  AuthorizationServerMetadata
	http      *http.Client
	userAgent string
}

func newOAuth(metadata AuthorizationServerMetadata, userAgent string, httpClient *http.Client) *OAuth {
	return &OAuth{metadata: metadata, http: httpClient, userAgent: userAgent}
}

// DiscoverOAuth fetches and validates the metadata document for this Control Plane. The issuer must
// equal the configured control URL: the CLI compares it with the iss parameter of every callback.
func (c *Client) DiscoverOAuth(ctx context.Context) (*OAuth, error) {
	metadata := AuthorizationServerMetadata{}
	if err := c.doJSON(ctx, http.MethodGet, metadataPath, "", nil, &metadata); err != nil {
		return nil, err
	}
	if metadata.Issuer != c.baseURL {
		return nil, fmt.Errorf("the authorization server reports issuer %q, but this CLI is configured for %q", metadata.Issuer, c.baseURL)
	}
	// Only the endpoints this deployment claims to have are validated; a flow whose endpoint is
	// absent reports that it is unavailable instead of failing discovery for every other flow.
	for name, endpoint := range map[string]string{
		"authorization_endpoint":        metadata.AuthorizationEndpoint,
		"token_endpoint":                metadata.TokenEndpoint,
		"device_authorization_endpoint": metadata.DeviceAuthorizationEndpoint,
		"revocation_endpoint":           metadata.RevocationEndpoint,
	} {
		if endpoint == "" && (name == "device_authorization_endpoint" || name == "revocation_endpoint") {
			continue
		}
		if err := sameOrigin(c.baseURL, endpoint); err != nil {
			return nil, fmt.Errorf("invalid %s: %s", name, err)
		}
	}
	if !contains(metadata.CodeChallengeMethodsSupported, "S256") {
		return nil, fmt.Errorf("the authorization server does not support PKCE with S256")
	}
	if !metadata.AuthorizationResponseIssParameterSupported {
		return nil, fmt.Errorf("the authorization server does not return the iss parameter")
	}
	return newOAuth(metadata, c.userAgent, c.http), nil
}

func (o *OAuth) Issuer() string { return o.metadata.Issuer }

func (o *OAuth) AuthorizationURL(state, challenge, redirectURI string) string {
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {ClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"scope":                 {ScopePlatform},
	}
	return o.metadata.AuthorizationEndpoint + "?" + query.Encode()
}

func (o *OAuth) StartDeviceAuthorization(ctx context.Context) (DeviceAuthorization, error) {
	if o.metadata.DeviceAuthorizationEndpoint == "" {
		return DeviceAuthorization{}, &OAuthError{
			Code:        "unsupported_grant_type",
			Description: "this ScopeDB deployment does not offer device login",
		}
	}
	form := url.Values{"client_id": {ClientID}, "scope": {ScopePlatform}}
	var response DeviceAuthorization
	if err := o.postForm(ctx, o.metadata.DeviceAuthorizationEndpoint, form, &response); err != nil {
		return DeviceAuthorization{}, err
	}
	if response.DeviceCode == "" || response.UserCode == "" || response.VerificationURI == "" || response.ExpiresIn <= 0 {
		return DeviceAuthorization{}, errors.New("ScopeDB returned an incomplete device authorization")
	}
	// The Console may use a different origin, but verification URLs must only open a web browser.
	for _, target := range []string{response.VerificationURI, response.VerificationURIComplete} {
		if target == "" {
			continue
		}
		parsed, err := url.Parse(target)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Hostname() == "" {
			return DeviceAuthorization{}, errors.New("ScopeDB returned an invalid device verification URL")
		}
	}
	return response, nil
}

func (o *OAuth) ExchangeAuthorizationCode(ctx context.Context, code, redirectURI, verifier string) (TokenSet, error) {
	return o.token(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {ClientID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
}

// PollDeviceAuthorization returns authorization_pending and slow_down as OAuthError values so the
// caller can keep polling; every other outcome is terminal.
func (o *OAuth) PollDeviceAuthorization(ctx context.Context, deviceCode string) (TokenSet, error) {
	return o.token(ctx, url.Values{
		"grant_type":  {GrantTypeDeviceCode},
		"client_id":   {ClientID},
		"device_code": {deviceCode},
	})
}

func (o *OAuth) RefreshToken(ctx context.Context, refreshToken string) (TokenSet, error) {
	return o.token(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {ClientID},
		"refresh_token": {refreshToken},
	})
}

// RevokeToken ends the whole grant behind a token. The endpoint answers 200 for unknown and
// already revoked tokens, so only transport and protocol failures are reported.
func (o *OAuth) RevokeToken(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	if o.metadata.RevocationEndpoint == "" {
		return &OAuthError{
			Code:        "unsupported_grant_type",
			Description: "this ScopeDB deployment does not offer token revocation",
		}
	}
	form := url.Values{"client_id": {ClientID}, "token": {token}}
	return o.postForm(ctx, o.metadata.RevocationEndpoint, form, nil)
}

func (o *OAuth) token(ctx context.Context, form url.Values) (TokenSet, error) {
	var response TokenSet
	err := o.postForm(ctx, o.metadata.TokenEndpoint, form, &response)
	return response, err
}

func (o *OAuth) postForm(ctx context.Context, endpoint string, form url.Values, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("create OAuth request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if o.userAgent != "" {
		request.Header.Set("User-Agent", o.userAgent)
	}

	response, err := o.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A transport failure is temporary. The refresh logic also relies on Status 0 to back off.
		return &OAuthError{Retryable: true, Err: err}
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return decodeOAuthError(response)
	}
	if output == nil {
		if _, err := readBounded(response.Body, maxErrorBody); err != nil {
			return &OAuthError{Status: response.StatusCode, Err: err}
		}
		return nil
	}
	data, err := readBounded(response.Body, maxSuccessBody)
	if err != nil {
		return &OAuthError{
			Status:    response.StatusCode,
			Retryable: !errors.Is(err, errResponseTooLarge),
			Err:       err,
		}
	}
	if err := json.Unmarshal(data, output); err != nil {
		return &OAuthError{Status: response.StatusCode, Code: "server_error", Description: "received an invalid response from ScopeDB", Err: err}
	}
	return nil
}

func decodeOAuthError(response *http.Response) error {
	data, readErr := readBounded(response.Body, maxErrorBody)
	result := &OAuthError{Status: response.StatusCode, RequestID: response.Header.Get("X-Request-ID"), Err: readErr}
	var payload struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if readErr == nil && json.Unmarshal(data, &payload) == nil {
		result.Code = payload.Error
		result.Description = payload.ErrorDescription
	}
	if result.Code == "" {
		result.Code = "server_error"
	}
	if result.Description == "" {
		result.Description = result.Code
	}
	result.Retryable = response.StatusCode == http.StatusRequestTimeout ||
		response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500
	result.RetryAfter = parseRetryAfter(response.Header.Get("Retry-After"))
	return result
}

func sameOrigin(origin, endpoint string) error {
	if strings.TrimSpace(endpoint) == "" {
		return fmt.Errorf("the authorization server does not advertise it")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("it is not a valid URL")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("it must use HTTP or HTTPS")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("it must not carry user information, query, or fragment")
	}
	expected, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("the configured control URL is invalid")
	}
	if !strings.EqualFold(parsed.Scheme, expected.Scheme) || !strings.EqualFold(parsed.Host, expected.Host) {
		return fmt.Errorf("it must be served from %s", origin)
	}
	return nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
