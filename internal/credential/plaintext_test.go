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
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlaintextStoreRoundTripAndDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "credentials.json")
	store := NewPlaintextStore(path)
	now := time.Date(2026, 9, 9, 1, 2, 3, 0, time.UTC)
	want := State{
		SessionToken:         "session-secret",
		WorkspaceID:          "ws-1",
		DataToken:            "data-secret",
		DataTokenWorkspaceID: "ws-1",
		DataTokenExpiresAt:   now,
	}
	const controlURL = "https://control.example.com"
	require.NoError(t, store.Save(controlURL, want))
	got, err := store.Load(controlURL)
	require.NoError(t, err)
	want.Version = currentStateVersion
	want.ControlURL = controlURL
	assert.Equal(t, want, got)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	require.NoError(t, store.Delete(controlURL))
	_, err = store.Load(controlURL)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestPlaintextStoreSeparatesOrigins(t *testing.T) {
	store := NewPlaintextStore(filepath.Join(t.TempDir(), "credentials.json"))
	for _, origin := range []string{"https://one.example.com", "https://two.example.com"} {
		require.NoError(t, store.Save(origin, State{SessionToken: origin, WorkspaceID: "ws"}))
	}
	for _, origin := range []string{"https://one.example.com", "https://two.example.com"} {
		state, err := store.Load(origin)
		require.NoError(t, err)
		assert.Equal(t, origin, state.SessionToken)
	}
}

func TestPlaintextStoreRejectsBroadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission check")
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"version":1,"profiles":{}}`), 0o644))
	_, err := NewPlaintextStore(path).Load("https://control.example.com")
	assert.ErrorContains(t, err, "unsafe permissions")
}
