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

package command

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/stretchr/testify/require"
)

func TestExpiredLoginReportsTheRemediationOnce(t *testing.T) {
	fake, store := setupCLITest(t)
	state := saveStoredLogin(t, store, fake.URL, "ws-1")
	state.AccessTokenExpiresAt = time.Now().Add(-time.Minute)
	require.NoError(t, store.Save(fake.URL, state))
	fake.TokenStatus = 400
	fake.TokenError = "invalid_grant"

	_, _, err := runFakeCommand(t, fake, "workspace", "list")
	require.ErrorIs(t, err, auth.ErrLoginExpired)
	require.Equal(t, 1, strings.Count(clierror.Compact(err), "run 'scope auth login'"))
	require.Equal(t, 1, strings.Count(clierror.Render(err), "run 'scope auth login'"))
}

func TestOAuthTransportFailureIsTemporary(t *testing.T) {
	err := NormalizeError(&controlplane.OAuthError{Retryable: true, Err: errors.New("connection refused")})
	require.Equal(t, clierror.ExitTemporary, clierror.ExitCode(err))
}
