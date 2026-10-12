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

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/scopedb/scopedb-cli/internal/auth"
)

// CatalogChange is the normalized state compared in one server transaction.
type CatalogChange struct {
	Before json.RawMessage `json:"before"`
	After  json.RawMessage `json:"after"`
}

// CatalogError preserves the HTTP outcome and server error code.
type CatalogError struct {
	Status    int    `json:"-"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"-"`
	Cause     error  `json:"-"`
}

func (e *CatalogError) Error() string { return e.Message }

func (e *CatalogError) Unwrap() error { return e.Cause }

// CatalogService implements the Catalog protocol, which the Go SDK does not yet expose.
type CatalogService struct{ HTTPClient *http.Client }

func (s *CatalogService) Get(ctx context.Context, access auth.Access, segments []string) (json.RawMessage, error) {
	body, _, err := s.request(ctx, access, http.MethodGet, segments, nil, false, "")
	return body, err
}

func (s *CatalogService) Mutate(ctx context.Context, access auth.Access, method string, segments []string, definition json.RawMessage, dryRun bool, etag string) (CatalogChange, string, error) {
	body, version, err := s.request(ctx, access, method, segments, definition, dryRun, etag)
	if err != nil {
		return CatalogChange{}, "", err
	}
	var result CatalogChange
	if err := json.Unmarshal(body, &result); err != nil || len(result.Before) == 0 || len(result.After) == 0 || version == "" {
		return CatalogChange{}, "", fmt.Errorf("invalid catalog response; verify the catalog before retrying")
	}
	return result, version, nil
}

func (s *CatalogService) request(ctx context.Context, access auth.Access, method string, segments []string, definition json.RawMessage, dryRun bool, etag string) (json.RawMessage, string, error) {
	endpoint, err := url.Parse(access.Endpoint)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, "", fmt.Errorf("invalid ScopeDB endpoint")
	}
	path := strings.TrimRight(endpoint.EscapedPath(), "/") + "/v1"
	for _, segment := range segments {
		path += "/" + url.PathEscape(segment)
	}
	endpoint.Path, _ = url.PathUnescape(path)
	endpoint.RawPath = path
	if dryRun {
		endpoint.RawQuery = "dry_run=true"
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(definition))
	if err != nil {
		return nil, "", err
	}
	request.Header.Set("Authorization", "Bearer "+access.APIKey)
	if len(definition) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		request.Header.Set("If-Match", etag)
	}
	client := s.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		if method != http.MethodGet && !dryRun {
			return nil, "", &CatalogError{Code: "catalog_commit_outcome_unknown", Message: "catalog apply could not be confirmed; read the catalog and plan again before retrying", Cause: err}
		}
		return nil, "", err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		if method != http.MethodGet && !dryRun {
			return nil, "", &CatalogError{Code: "catalog_commit_outcome_unknown", Message: "catalog apply response could not be read; read the catalog and plan again before retrying", Cause: err}
		}
		return nil, "", fmt.Errorf("read catalog response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		failure := &CatalogError{Status: response.StatusCode, RequestID: response.Header.Get("X-Request-ID")}
		if json.Unmarshal(body, failure) != nil || failure.Message == "" {
			failure.Message = fmt.Sprintf("catalog request failed: HTTP %d", response.StatusCode)
		}
		if access.APIKey != "" {
			failure.Message = strings.ReplaceAll(failure.Message, access.APIKey, "[redacted]")
		}
		return nil, "", failure
	}
	return body, response.Header.Get("ETag"), nil
}
