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

package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/require"
)

type failingReloadStore struct {
	state credential.State
	loads int
	err   error
}

func (s *failingReloadStore) Load(string) (credential.State, error) {
	s.loads++
	if s.loads > 1 {
		return credential.State{}, s.err
	}
	return s.state, nil
}

func (s *failingReloadStore) Save(string, credential.State) error    { return nil }
func (s *failingReloadStore) Replace(string, credential.State) error { return nil }
func (s *failingReloadStore) Delete(string) error                    { return nil }

func TestResolveDataAccessPropagatesRefreshSaveFailure(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	keyringWrite := &credential.KeyringError{Op: "write", Err: errors.New("keyring locked")}
	store := &memoryStore{present: true, state: loginState(now, now.Add(30*time.Second)), saveErr: keyringWrite}
	oauth := &fakeOAuth{results: []tokenOutcome{{tokens: accessTokens("oat_new", "ort_new")}}}
	control := &fakeControl{}
	manager := newManager(t, store, control, oauth, now)
	manager.OIDC = oidcEnv("ws-b", "ci.jwt.token")

	access, err := manager.ResolveDataAccess(t.Context())

	var keyringErr *credential.KeyringError
	require.ErrorAs(t, err, &keyringErr, "a failed credential write must surface instead of falling back to OIDC")
	require.Empty(t, control.oidcExchangeArg, "the OIDC exchange must not run after a stored login was selected")
	require.Empty(t, access.WorkspaceID, "no access may be returned for another workspace")
	require.Equal(t, 1, oauth.refreshCalls())
}

func TestResolveDataAccessPropagatesKeyringReadFailureDuringRefresh(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	keyringRead := &credential.KeyringError{Op: "read", Err: errors.New("secret service unavailable")}
	store := &failingReloadStore{state: loginState(now, now.Add(30*time.Second)), err: keyringRead}
	control := &fakeControl{}
	manager := newManager(t, store, control, &fakeOAuth{}, now)
	manager.OIDC = oidcEnv("ws-b", "ci.jwt.token")

	access, err := manager.ResolveDataAccess(t.Context())

	var keyringErr *credential.KeyringError
	require.ErrorAs(t, err, &keyringErr, "a keyring failure after the login was read must surface instead of falling back to OIDC")
	require.Empty(t, control.oidcExchangeArg, "the OIDC exchange must not run after a stored login was selected")
	require.Empty(t, access.WorkspaceID, "no access may be returned for another workspace")
}
