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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

func TestOAuthTransportFailureIsRetryable(t *testing.T) {
	client := newOAuth(AuthorizationServerMetadata{
		Issuer:        "https://control.example.com",
		TokenEndpoint: "https://control.example.com/oauth/token",
	}, "", &http.Client{Transport: failingTransport{}})

	_, err := client.RefreshToken(context.Background(), "ort_refresh")
	var protocol *OAuthError
	require.ErrorAs(t, err, &protocol)
	require.True(t, protocol.Retryable)
}

func TestOAuthResponseValidationIsNotRetryable(t *testing.T) {
	for _, response := range []struct {
		name string
		body string
	}{
		{"invalid_json", `{"access_token":`},
		{"too_large", strings.Repeat(" ", maxSuccessBody) + `{}`},
	} {
		t.Run(response.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(response.body))
			}))
			t.Cleanup(server.Close)
			client := newOAuth(AuthorizationServerMetadata{TokenEndpoint: server.URL}, "", server.Client())

			_, err := client.RefreshToken(t.Context(), "ort_refresh")
			var protocol *OAuthError
			require.ErrorAs(t, err, &protocol)
			require.Equal(t, http.StatusOK, protocol.Status)
			require.False(t, protocol.Retryable)
		})
	}
}
