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

package credential

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type faultStore struct {
	Store
	loadErr   error
	saveErr   error
	deleteErr error
	deletes   int
}

func (s *faultStore) Load(origin string) (State, error) {
	if s.loadErr != nil {
		return State{}, s.loadErr
	}
	return s.Store.Load(origin)
}

func (s *faultStore) Save(origin string, state State) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.Store.Save(origin, state)
}

func (s *faultStore) Delete(origin string) error {
	s.deletes++
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.Store.Delete(origin)
}

// Two separate files stand in for independent storage services so faults can
// be injected without changing the machine's keyring.
func testStores(t *testing.T) (*Stores, *faultStore, *faultStore) {
	t.Helper()
	keyring := &faultStore{Store: NewPlaintextStore(filepath.Join(t.TempDir(), "keyring.json"), "")}
	plaintext := &faultStore{Store: NewPlaintextStore(filepath.Join(t.TempDir(), "credentials.json"), "")}
	return &Stores{Keyring: keyring, Plaintext: plaintext}, keyring, plaintext
}

func storedTokens(name string) State {
	return State{AccessToken: "access-" + name, RefreshToken: "refresh-" + name}
}

func TestNewLoginSwitchesStoresAndPreservesOtherOrigins(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		name := SourceKeyring
		if insecure {
			name = SourcePlaintext
		}
		t.Run(name, func(t *testing.T) {
			stores, keyring, plaintext := testStores(t)
			const origin = "https://control.example.com"
			const other = "https://other.example.com"
			previous, destination := plaintext, keyring
			if insecure {
				previous, destination = keyring, plaintext
			}
			require.NoError(t, previous.Save(origin, storedTokens("old")))
			require.NoError(t, previous.Save(other, storedTokens("other")))
			stores.InsecureStorage = insecure
			require.NoError(t, stores.Replace(origin, storedTokens("new")))
			state, err := stores.Load(origin)
			require.NoError(t, err)
			require.Equal(t, name, state.Source)
			require.Equal(t, "access-new", state.AccessToken)
			_, err = previous.Load(origin)
			require.ErrorIs(t, err, ErrNotFound)
			otherState, err := previous.Load(other)
			require.NoError(t, err)
			require.Equal(t, "access-other", otherState.AccessToken)
			_, err = destination.Load(origin)
			require.NoError(t, err)
		})
	}
}

func TestUpdatesKeepTheirSourceRegardlessOfLoginFlag(t *testing.T) {
	for _, source := range []string{SourceKeyring, SourcePlaintext} {
		t.Run(source, func(t *testing.T) {
			stores, keyring, plaintext := testStores(t)
			const origin = "https://control.example.com"
			destination, unused := keyring, plaintext
			stores.InsecureStorage = true
			if source == SourcePlaintext {
				destination, unused = plaintext, keyring
				stores.InsecureStorage = false
			}
			require.NoError(t, destination.Save(origin, storedTokens("old")))
			state, err := stores.Load(origin)
			require.NoError(t, err)
			state.AccessToken = "access-rotated"
			require.NoError(t, stores.Save(origin, state))
			updated, err := destination.Load(origin)
			require.NoError(t, err)
			require.Equal(t, state.AccessToken, updated.AccessToken)
			require.Zero(t, unused.deletes)
			_, err = unused.Load(origin)
			require.ErrorIs(t, err, ErrNotFound)
		})
	}
}

func TestKeyringUpdateFailureDoesNotDowngrade(t *testing.T) {
	stores, keyring, plaintext := testStores(t)
	const origin = "https://control.example.com"
	require.NoError(t, keyring.Save(origin, storedTokens("old")))
	state, err := stores.Load(origin)
	require.NoError(t, err)
	keyring.saveErr = os.ErrPermission
	state.AccessToken = "access-rotated"
	require.ErrorIs(t, stores.Save(origin, state), os.ErrPermission)
	_, err = plaintext.Load(origin)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestFallbackAndLogoutNeverReviveAnInaccessibleKeyringEntry(t *testing.T) {
	stores, keyring, plaintext := testStores(t)
	const origin = "https://control.example.com"
	require.NoError(t, keyring.Save(origin, storedTokens("old")))
	keyring.loadErr = os.ErrPermission
	keyring.saveErr = os.ErrPermission
	keyring.deleteErr = os.ErrPermission
	warnings := 0
	stores.OnPlaintext = func(fallback, cleanup error) {
		warnings++
		require.ErrorIs(t, fallback, os.ErrPermission)
		require.ErrorIs(t, cleanup, os.ErrPermission)
	}
	require.NoError(t, stores.Replace(origin, storedTokens("new")))
	require.Equal(t, 1, warnings)
	// Reading the new fallback does not require access to the broken keyring.
	state, err := stores.Load(origin)
	require.NoError(t, err)
	require.Equal(t, "access-new", state.AccessToken)
	keyring.loadErr = nil
	state, err = stores.Load(origin)
	require.NoError(t, err)
	require.Equal(t, "access-new", state.AccessToken)

	require.ErrorIs(t, stores.Delete(origin), os.ErrPermission)
	cleared, err := plaintext.Load(origin)
	require.NoError(t, err)
	require.True(t, cleared.Cleared)
	require.Empty(t, cleared.AccessToken)
	require.Empty(t, cleared.RefreshToken)
	require.Empty(t, cleared.DataToken)
	// A new command still sees a logout after the keyring recovers.
	next := &Stores{Keyring: keyring, Plaintext: plaintext}
	_, err = next.Load(origin)
	require.ErrorIs(t, err, ErrNotFound)
	keyring.deleteErr = nil
	keyring.saveErr = nil
	require.NoError(t, next.Delete(origin))
	_, err = keyring.Load(origin)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = plaintext.Load(origin)
	require.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, next.Replace(origin, storedTokens("next")))
	state, err = next.Load(origin)
	require.NoError(t, err)
	require.Equal(t, SourceKeyring, state.Source)
}

func TestFailedFallbackPreservesExistingCredentials(t *testing.T) {
	stores, keyring, plaintext := testStores(t)
	const origin = "https://control.example.com"
	require.NoError(t, keyring.Save(origin, storedTokens("old")))
	keyring.saveErr = errors.New("keyring write failed")
	plaintext.saveErr = os.ErrPermission
	stores.OnPlaintext = func(error, error) { t.Fatal("unsuccessful fallback must not report success") }
	err := stores.Replace(origin, storedTokens("new"))
	require.ErrorIs(t, err, keyring.saveErr)
	require.ErrorIs(t, err, os.ErrPermission)
	state, err := stores.Load(origin)
	require.NoError(t, err)
	require.Equal(t, "access-old", state.AccessToken)
}

func TestFailedPlaintextCleanupPreservesOldLogin(t *testing.T) {
	stores, keyring, plaintext := testStores(t)
	const origin = "https://control.example.com"
	require.NoError(t, plaintext.Save(origin, storedTokens("old")))
	plaintext.deleteErr = os.ErrPermission
	require.ErrorIs(t, stores.Replace(origin, storedTokens("new")), os.ErrPermission)
	state, err := stores.Load(origin)
	require.NoError(t, err)
	require.Equal(t, "access-old", state.AccessToken)
	_, err = keyring.Load(origin)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestRestoreReportsIncompleteKeyringCleanup(t *testing.T) {
	stores, keyring, plaintext := testStores(t)
	const origin = "https://control.example.com"
	require.NoError(t, plaintext.Save(origin, storedTokens("previous")))
	previous, err := stores.Load(origin)
	require.NoError(t, err)
	require.NoError(t, stores.Replace(origin, storedTokens("new")))
	keyring.deleteErr = os.ErrPermission
	require.ErrorIs(t, stores.Replace(origin, previous), os.ErrPermission)
	// The previous login is authoritative despite the failed cleanup.
	current, err := stores.Load(origin)
	require.NoError(t, err)
	require.Equal(t, previous.AccessToken, current.AccessToken)
}
