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

	query := parsed.Query()
	query.Set("code", "code-1")
	query.Set("state", "state-1")
	query.Set("iss", "https://control.example.com")
	parsed.RawQuery = query.Encode()

	response, err := http.Get(parsed.String())
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "no-store", response.Header.Get("Cache-Control"))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	callback, err := listener.Wait(ctx)
	require.NoError(t, err)
	assert.Equal(t, Callback{
		Code:   "code-1",
		State:  "state-1",
		Issuer: "https://control.example.com",
	}, callback)

	// A later callback never replaces the first one.
	response, err = http.Get(parsed.String())
	require.NoError(t, err)
	_ = response.Body.Close()
	select {
	case other := <-listener.results:
		assert.Equal(t, callback, other)
	default:
	}
}

func TestLoopbackReportsAuthorizationErrors(t *testing.T) {
	listener, err := NewLoopback()
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	parsed, err := url.Parse(listener.RedirectURI())
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("error", "access_denied")
	query.Set("error_description", "the user denied the request")
	query.Set("state", "state-1")
	parsed.RawQuery = query.Encode()
	response, err := http.Get(parsed.String())
	require.NoError(t, err)
	_ = response.Body.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	callback, err := listener.Wait(ctx)
	require.NoError(t, err)
	assert.Equal(t, "access_denied", callback.Error)
	assert.Equal(t, "the user denied the request", callback.ErrorDescription)
	assert.Empty(t, callback.Code)
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
