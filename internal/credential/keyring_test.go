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
		`{"session_token":"private-secret"`,
		`{"data_token_expires_at":"private-secret"}`,
	} {
		require.NoError(t, keyring.Set(keyringService, profileKey(controlURL), encoded))
		_, err := store.Load(controlURL)
		require.ErrorIs(t, err, ErrInvalidState)
		require.NotContains(t, err.Error(), "private-secret")
		require.NoError(t, store.Save(controlURL, State{SessionToken: "new-session"}))
		state, err := store.Load(controlURL)
		require.NoError(t, err)
		require.Equal(t, "new-session", state.SessionToken)
	}
}

func TestKeyringStorePreservesAccessErrors(t *testing.T) {
	keyring.MockInitWithError(os.ErrPermission)
	t.Cleanup(keyring.MockInit)
	_, err := NewKeyringStore().Load("https://control.example.com")
	require.ErrorIs(t, err, os.ErrPermission)
	require.NotErrorIs(t, err, ErrInvalidState)
}
