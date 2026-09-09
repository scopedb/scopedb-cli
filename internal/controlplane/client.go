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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxSuccessBody = 8 << 20
	maxErrorBody   = 64 << 10
)

// Error represents a control-plane HTTP or transport failure.
type Error struct {
	Status     int
	Message    string
	RequestID  string
	Retryable  bool
	RetryAfter time.Duration
	Err        error
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "control-plane request failed"
}

func (e *Error) Unwrap() error { return e.Err }

// Client is the typed boundary around the ScopeDB SaaS control-plane API.
type Client struct {
	baseURL   string
	http      *http.Client
	userAgent string
}

// NewClient constructs a client. The supplied HTTP client remains owned by the caller.
func NewClient(baseURL, userAgent string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse control URL: %w", err)
	}
	if (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return nil, fmt.Errorf("control URL must be an absolute HTTP(S) URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("control URL must not contain userinfo, query, or fragment")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{baseURL: parsed.String(), http: httpClient, userAgent: userAgent}, nil
}

func (c *Client) BeginLogin(ctx context.Context, email string) (LoginBeginResponse, error) {
	var response LoginBeginResponse
	err := c.doJSON(ctx, http.MethodPost, "/api/login", "", map[string]string{"email": email}, &response)
	return response, err
}

func (c *Client) VerifyLogin(ctx context.Context, challenge, code string) (LoginResponse, error) {
	var response LoginResponse
	err := c.doJSON(ctx, http.MethodPost, "/api/login/verify", "", map[string]string{
		"login_challenge": challenge,
		"code":            code,
	}, &response)
	return response, err
}

func (c *Client) GetSession(ctx context.Context, token string) (Session, error) {
	var response Session
	err := c.doJSON(ctx, http.MethodGet, "/api/session", token, nil, &response)
	return response, err
}

func (c *Client) DeleteSession(ctx context.Context, token string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/session", token, nil, nil)
}

func (c *Client) SelectWorkspace(ctx context.Context, token, workspaceID string) (LoginResponse, error) {
	var response LoginResponse
	err := c.doJSON(ctx, http.MethodPost, "/api/session/workspace", token, map[string]string{
		"workspace_id": workspaceID,
	}, &response)
	return response, err
}

func (c *Client) GetWorkspace(ctx context.Context, token, workspaceID string) (WorkspaceDetails, error) {
	var response WorkspaceDetails
	err := c.doJSON(ctx, http.MethodGet, workspacePath(workspaceID), token, nil, &response)
	return response, err
}

func (c *Client) ExchangeToken(ctx context.Context, token, workspaceID string) (TokenExchangeResponse, error) {
	var response TokenExchangeResponse
	err := c.doJSON(ctx, http.MethodPost, workspacePath(workspaceID)+"/token-exchange", token, struct{}{}, &response)
	return response, err
}

func (c *Client) ListAPIKeys(ctx context.Context, token, workspaceID string) ([]APIKey, error) {
	var response []APIKey
	err := c.doJSON(ctx, http.MethodGet, workspacePath(workspaceID)+"/api-keys", token, nil, &response)
	if response == nil && err == nil {
		response = []APIKey{}
	}
	return response, err
}

func (c *Client) CreateAPIKey(ctx context.Context, token, workspaceID string, request CreateAPIKeyRequest) (APIKey, error) {
	var response APIKey
	err := c.doJSON(ctx, http.MethodPost, workspacePath(workspaceID)+"/api-keys", token, request, &response)
	return response, err
}

func (c *Client) RevokeAPIKey(ctx context.Context, token, workspaceID, name string) error {
	return c.doJSON(ctx, http.MethodDelete, workspacePath(workspaceID)+"/api-keys/"+url.PathEscape(name), token, nil, nil)
}

func (c *Client) Health(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodGet, "/healthz", "", nil, nil)
}

func workspacePath(workspaceID string) string {
	return "/api/workspaces/" + url.PathEscape(workspaceID)
}

func (c *Client) doJSON(ctx context.Context, method, path, token string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode control-plane request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("create control-plane request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if c.userAgent != "" {
		request.Header.Set("User-Agent", c.userAgent)
	}

	response, err := c.http.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return &Error{Message: "cannot reach ScopeDB control plane", Retryable: true, Err: err}
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return decodeError(response)
	}
	if output == nil {
		_, err := readBounded(response.Body, maxSuccessBody)
		if err != nil {
			return &Error{Status: response.StatusCode, Message: "control-plane response is too large", RequestID: response.Header.Get("X-Request-ID"), Err: err}
		}
		return nil
	}
	data, err := readBounded(response.Body, maxSuccessBody)
	if err != nil {
		return &Error{Status: response.StatusCode, Message: "control-plane response is too large", RequestID: response.Header.Get("X-Request-ID"), Err: err}
	}
	if err := json.Unmarshal(data, output); err != nil {
		return &Error{Status: response.StatusCode, Message: "received an invalid response from ScopeDB", RequestID: response.Header.Get("X-Request-ID"), Err: err}
	}
	return nil
}

func decodeError(response *http.Response) error {
	data, readErr := readBounded(response.Body, maxErrorBody)
	message := strings.TrimSpace(string(data))
	if readErr != nil {
		message = "ScopeDB returned an oversized error response"
	}
	requestID := response.Header.Get("X-Request-ID")
	var payload struct {
		Message   json.RawMessage `json:"message"`
		RequestID string          `json:"request_id"`
		Error     *struct {
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if readErr == nil && json.Unmarshal(data, &payload) == nil {
		var plainMessage string
		if json.Unmarshal(payload.Message, &plainMessage) == nil && plainMessage != "" {
			message = plainMessage
		}
		if payload.Error != nil && payload.Error.Message != "" {
			message = payload.Error.Message
		}
		if payload.RequestID != "" {
			requestID = payload.RequestID
		} else if payload.Error != nil && payload.Error.RequestID != "" {
			requestID = payload.Error.RequestID
		}
	}
	if message == "" {
		message = response.Status
	}
	return &Error{
		Status:     response.StatusCode,
		Message:    message,
		RequestID:  requestID,
		Retryable:  response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500,
		RetryAfter: parseRetryAfter(response.Header.Get("Retry-After")),
		Err:        readErr,
	}
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return data[:limit], fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

func parseRetryAfter(value string) time.Duration {
	if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if retryAt, err := http.ParseTime(value); err == nil {
		if delay := time.Until(retryAt); delay > 0 {
			return delay
		}
	}
	return 0
}
