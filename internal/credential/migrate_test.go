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
	"path/filepath"
	"testing"

	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/stretchr/testify/require"
	keyring "github.com/zalando/go-keyring"
)

func TestMigrationResumesWithoutReplayingRefreshTokens(t *testing.T) {
	for _, source := range []string{SourceKeyring, SourcePlaintext} {
		t.Run(source, func(t *testing.T) {
			legacy, oldKeyring, oldPlaintext := testStores(t)
			target, _, _ := testStores(t)
			other, _, _ := testStores(t)
			const origin = "https://control.example.com"
			original := storedTokens("legacy")
			original.WorkspaceID = "ws-old"
			store := oldKeyring
			if source == SourcePlaintext {
				store = oldPlaintext
			}
			require.NoError(t, store.Save(origin, original))
			require.NoError(t, store.Save("https://other.example.com", storedTokens("other-origin")))
			migrated, found, err := MigrateLegacy(origin, "default-ref", legacy, target)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, source, migrated.Source)
			require.Equal(t, "ws-old", migrated.WorkspaceID)
			require.NotEmpty(t, migrated.LoginID)
			// A retry after target refresh must never replace it with the legacy rotation.
			migrated.RefreshToken = "rotated-refresh"
			require.NoError(t, target.Save(origin, migrated))
			retry, found, err := MigrateLegacy(origin, "default-ref", legacy, target)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, "rotated-refresh", retry.RefreshToken)
			_, found, err = MigrateLegacy(origin, "another-ref", legacy, other)
			require.NoError(t, err)
			require.False(t, found)
			_, err = legacy.Load(origin)
			require.ErrorIs(t, err, ErrNotFound)
			raw, err := store.Load(origin)
			require.NoError(t, err)
			require.Empty(t, raw.RefreshToken)
			require.True(t, raw.Cleared)
			remaining, err := store.Load("https://other.example.com")
			require.NoError(t, err)
			require.Equal(t, "refresh-other-origin", remaining.RefreshToken)
		})
	}
}

func TestMigrationClaimsBeforeCopyAndRetriesAfterWriteFailure(t *testing.T) {
	legacy, _, source := testStores(t)
	target, _, destination := testStores(t)
	other, _, _ := testStores(t)
	const origin = "https://control.example.com"
	require.NoError(t, source.Save(origin, storedTokens("legacy")))
	destination.saveErr = os.ErrPermission
	_, _, err := MigrateLegacy(origin, "owner", legacy, target)
	require.ErrorIs(t, err, os.ErrPermission)
	_, err = legacy.Load(origin)
	require.ErrorIs(t, err, ErrNotFound)
	_, found, err := MigrateLegacy(origin, "another", legacy, other)
	require.NoError(t, err)
	require.False(t, found)
	destination.saveErr = nil
	migrated, found, err := MigrateLegacy(origin, "owner", legacy, target)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "refresh-legacy", migrated.RefreshToken)
}

func TestMigrationCannotReviveLogoutOrDuplicateLegacyKeyring(t *testing.T) {
	legacy, globalKeyring, oldFile := testStores(t)
	target, _, _ := testStores(t)
	const origin = "https://control.example.com"
	require.NoError(t, globalKeyring.Save(origin, storedTokens("shared")))
	_, found, err := MigrateLegacy(origin, "first-directory", legacy, target)
	require.NoError(t, err)
	require.True(t, found)
	require.NoError(t, target.Delete(origin))
	_, found, err = MigrateLegacy(origin, "first-directory", legacy, target)
	require.NoError(t, err)
	require.False(t, found)
	// A legacy file copied before migration cannot adopt the same old grant elsewhere.
	require.NoError(t, oldFile.Save(origin, storedTokens("shared")))
	another, _, _ := testStores(t)
	_, found, err = MigrateLegacy(origin, "second-directory", legacy, another)
	require.NoError(t, err)
	require.False(t, found)
}

func TestCredentialReferencesIsolateProfilesAndDirectories(t *testing.T) {
	keyring.MockInit()
	t.Cleanup(keyring.MockInit)
	firstDir, secondDir := t.TempDir(), t.TempDir()
	const origin = "https://control.example.com"
	stores := []*Stores{}
	for _, entry := range []struct{ directory, name string }{{firstDir, "dev"}, {firstDir, "prod"}, {secondDir, "dev"}} {
		reference := config.CredentialReference(config.Paths{Directory: entry.directory}, entry.name)
		stores = append(stores, &Stores{Keyring: NewKeyringStore(reference), Plaintext: NewPlaintextStore(filepath.Join(entry.directory, "credentials.json"), reference)})
	}
	for i, store := range stores {
		require.NoError(t, store.Replace(origin, storedTokens(string(rune('a'+i)))))
	}
	// A failed keyring cleanup leaves a tombstone only for the selected profile.
	faulty := &faultStore{Store: stores[0].Keyring, deleteErr: os.ErrPermission}
	stores[0].Keyring = faulty
	require.ErrorIs(t, stores[0].Delete(origin), os.ErrPermission)
	_, err := stores[0].Load(origin)
	require.ErrorIs(t, err, ErrNotFound)
	for _, store := range stores[1:] {
		_, err := store.Load(origin)
		require.NoError(t, err)
	}
	faulty.deleteErr = nil
	require.NoError(t, stores[0].Delete(origin))
	// Backend changes and origin lookups stay within the same reference.
	stores[1].InsecureStorage = true
	require.NoError(t, stores[1].Replace(origin, storedTokens("file")))
	updated, err := stores[1].Load(origin)
	require.NoError(t, err)
	require.Equal(t, SourcePlaintext, updated.Source)
	unchanged, err := stores[2].Load(origin)
	require.NoError(t, err)
	require.Equal(t, "refresh-c", unchanged.RefreshToken)
	_, err = stores[1].Load("https://another.example.com")
	require.ErrorIs(t, err, ErrNotFound)
}
