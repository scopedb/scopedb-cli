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
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	keyring "github.com/zalando/go-keyring"
)

func TestKeyringStoreReplacesInvalidEntry(t *testing.T) {
	keyring.MockInit()
	t.Cleanup(keyring.MockInit)
	store := NewKeyringStore()
	const controlURL = "https://control.example.com"
	for _, encoded := range []string{
		`{"access_token":"private-secret"`,
		`{"data_token_expires_at":"private-secret"}`,
	} {
		require.NoError(t, keyring.Set(keyringService, profileKey(controlURL), encoded))
		_, err := store.Load(controlURL)
		require.ErrorIs(t, err, ErrInvalidState)
		require.NotContains(t, err.Error(), "private-secret")
		require.NoError(t, store.Save(controlURL, State{AccessToken: "oat_new", RefreshToken: "ort_new"}))
		state, err := store.Load(controlURL)
		require.NoError(t, err)
		require.Equal(t, "oat_new", state.AccessToken)
	}
}

func TestKeyringStorePreservesAccessErrors(t *testing.T) {
	keyring.MockInitWithError(os.ErrPermission)
	t.Cleanup(keyring.MockInit)
	store := NewKeyringStore()
	const controlURL = "https://control.example.com"
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{"read", func() error {
			_, err := store.Load(controlURL)
			return err
		}},
		{"write", func() error { return store.Save(controlURL, State{}) }},
		{"delete", func() error { return store.Delete(controlURL) }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			err := operation.run()
			var keyringErr *KeyringError
			require.ErrorAs(t, err, &keyringErr)
			require.ErrorIs(t, err, os.ErrPermission)
			require.NotErrorIs(t, err, ErrNotFound)
			require.NotErrorIs(t, err, ErrInvalidState)
		})
	}
}
