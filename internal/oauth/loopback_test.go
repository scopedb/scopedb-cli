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

package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPKCEChallengeMatchesVerifier(t *testing.T) {
	first, err := NewPKCE()
	require.NoError(t, err)
	second, err := NewPKCE()
	require.NoError(t, err)
	require.NotEqual(t, first.Verifier, second.Verifier)

	for _, pkce := range []PKCE{first, second} {
		require.Len(t, pkce.Verifier, 64)
		for _, char := range pkce.Verifier {
			require.True(t, strings.ContainsRune("0123456789abcdef", char), "unexpected verifier character %q", char)
		}
		digest := sha256.Sum256([]byte(pkce.Verifier))
		require.Equal(t, base64.RawURLEncoding.EncodeToString(digest[:]), pkce.Challenge)
		require.NotContains(t, pkce.Challenge, "=")
	}
}

func TestStateIsUnique(t *testing.T) {
	first, err := NewState()
	require.NoError(t, err)
	second, err := NewState()
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	require.Len(t, first, 64)
}

func TestLoopbackAcceptsOneCallback(t *testing.T) {
	listener, err := NewLoopback()
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	parsed, err := url.Parse(listener.RedirectURI())
	require.NoError(t, err)
	assert.Equal(t, "http", parsed.Scheme)
	assert.Equal(t, "127.0.0.1", parsed.Hostname())
	assert.Equal(t, "/callback", parsed.Path)
	assert.NotEmpty(t, parsed.Port())

	callbackURL := func(code, state string) string {
		copied := *parsed
		query := parsed.Query()
		query.Set("code", code)
		query.Set("state", state)
		query.Set("iss", "https://control.example.com")
		copied.RawQuery = query.Encode()
		return copied.String()
	}
	for _, target := range []string{callbackURL("code-1", "state-1"), callbackURL("code-2", "state-2")} {
		response, err := http.Get(target)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, "no-store", response.Header.Get("Cache-Control"))
		_ = response.Body.Close()
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	callback, err := listener.Wait(ctx)
	require.NoError(t, err)
	assert.Equal(t, Callback{
		Code:   "code-1",
		State:  "state-1",
		Issuer: "https://control.example.com",
	}, callback)

	select {
	case other := <-listener.results:
		t.Fatalf("listener delivered a second callback: %+v", other)
	default:
	}
}

func TestLoopbackRendersCallbackOutcome(t *testing.T) {
	for _, tt := range []struct {
		name     string
		callback Callback
		received bool
	}{
		{name: "authorization", callback: Callback{Code: "private-code"}, received: true},
		{name: "denied", callback: Callback{Error: "access_denied"}},
		{name: "error with code", callback: Callback{Code: "private-code", Error: "server_error"}},
		{name: "missing code"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := NewLoopback()
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })

			tt.callback.State = "private-state"
			tt.callback.Issuer = "https://private-issuer.example.com"
			tt.callback.ErrorDescription = "<script>alert('private-description')</script>"
			query := url.Values{
				"code":              {tt.callback.Code},
				"state":             {tt.callback.State},
				"iss":               {tt.callback.Issuer},
				"error":             {tt.callback.Error},
				"error_description": {tt.callback.ErrorDescription},
			}
			response, err := http.Get(listener.RedirectURI() + "?" + query.Encode())
			require.NoError(t, err)
			defer func() { _ = response.Body.Close() }()
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			page := string(body)
			assert.Equal(t, http.StatusOK, response.StatusCode)
			assert.Equal(t, "text/html; charset=utf-8", response.Header.Get("Content-Type"))
			assert.Equal(t, "no-store", response.Header.Get("Cache-Control"))
			assert.Equal(t, "no-referrer", response.Header.Get("Referrer-Policy"))
			assert.Contains(t, response.Header.Get("Content-Security-Policy"), "default-src 'none'")
			if tt.received {
				assert.Contains(t, page, "Authorization received")
				assert.NotContains(t, page, "Sign-in not completed")
			} else {
				assert.Contains(t, page, "Sign-in not completed")
				assert.Contains(t, page, "scope auth login")
				assert.NotContains(t, page, "Authorization received")
			}
			for _, sensitive := range []string{"private-code", "private-state", "private-issuer", "private-description"} {
				assert.NotContains(t, page, sensitive)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			callback, err := listener.Wait(ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.callback, callback)
		})
	}
}

func TestLoopbackIgnoresOtherPaths(t *testing.T) {
	listener, err := NewLoopback()
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	base := strings.TrimSuffix(listener.RedirectURI(), "/callback")
	response, err := http.Get(base + "/favicon.ico")
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, response.StatusCode)
}

func TestLoopbackWaitStopsWithContext(t *testing.T) {
	listener, err := NewLoopback()
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err = listener.Wait(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
