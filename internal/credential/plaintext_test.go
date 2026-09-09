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
	"runtime"
	"testing"
	"time"
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
	if err := store.Save("https://control.example.com", want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := store.Load("https://control.example.com")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.SessionToken != want.SessionToken || got.DataToken != want.DataToken || got.WorkspaceID != want.WorkspaceID || !got.DataTokenExpiresAt.Equal(now) {
		t.Errorf("Load() = %#v, want %#v", got, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		if gotMode, wantMode := info.Mode().Perm(), os.FileMode(0o600); gotMode != wantMode {
			t.Errorf("mode = %03o, want %03o", gotMode, wantMode)
		}
	}
	if err := store.Delete("https://control.example.com"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Load("https://control.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() after delete error = %v, want ErrNotFound", err)
	}
}

func TestPlaintextStoreSeparatesOrigins(t *testing.T) {
	store := NewPlaintextStore(filepath.Join(t.TempDir(), "credentials.json"))
	for _, origin := range []string{"https://one.example.com", "https://two.example.com"} {
		if err := store.Save(origin, State{SessionToken: origin, WorkspaceID: "ws"}); err != nil {
			t.Fatalf("Save(%q) error = %v", origin, err)
		}
	}
	for _, origin := range []string{"https://one.example.com", "https://two.example.com"} {
		state, err := store.Load(origin)
		if err != nil {
			t.Fatalf("Load(%q) error = %v", origin, err)
		}
		if state.SessionToken != origin {
			t.Errorf("Load(%q).SessionToken = %q", origin, state.SessionToken)
		}
	}
}

func TestPlaintextStoreRejectsBroadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission check")
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"profiles":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := NewPlaintextStore(path).Load("https://control.example.com")
	if err == nil {
		t.Fatal("Load() error = nil, want unsafe permissions error")
	}
}
