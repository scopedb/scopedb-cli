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

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadPrecedence(t *testing.T) {
	directory := t.TempDir()
	paths := Paths{
		Directory:       directory,
		Config:          filepath.Join(directory, "config.toml"),
		CredentialsFile: filepath.Join(directory, "credentials.json"),
	}
	fileConfig := Config{
		ControlURL:      "https://file-control.example.com/",
		ConsoleURL:      "https://file-console.example.com/",
		CredentialStore: CredentialStorePlaintext,
	}
	if err := Save(paths, fileConfig); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	t.Setenv("SCOPEDB_CONTROL_URL", "https://env-control.example.com/")
	t.Setenv("SCOPEDB_CONSOLE_URL", "https://env-console.example.com/")
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", CredentialStoreKeyring)
	cfg, err := Load(paths, Overrides{ControlURL: "https://flag-control.example.com/"})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, want := cfg.ControlURL, "https://flag-control.example.com"; got != want {
		t.Errorf("ControlURL = %q, want %q", got, want)
	}
	if got, want := cfg.ConsoleURL, "https://env-console.example.com"; got != want {
		t.Errorf("ConsoleURL = %q, want %q", got, want)
	}
	if got, want := cfg.CredentialStore, CredentialStoreKeyring; got != want {
		t.Errorf("CredentialStore = %q, want %q", got, want)
	}
}

func TestResolvePathsUsesOverride(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "nested")
	t.Setenv("SCOPEDB_CONFIG_DIR", directory)
	paths, err := ResolvePaths()
	if err != nil {
		t.Fatalf("ResolvePaths() error = %v", err)
	}
	if paths.Directory != directory {
		t.Errorf("Directory = %q, want %q", paths.Directory, directory)
	}
	if paths.Config != filepath.Join(directory, "config.toml") {
		t.Errorf("Config = %q", paths.Config)
	}
}

func TestSaveRestrictsPermissions(t *testing.T) {
	directory := t.TempDir()
	paths := Paths{Directory: directory, Config: filepath.Join(directory, "config.toml")}
	if err := Save(paths, Config{
		ControlURL:      DefaultControlURL,
		ConsoleURL:      DefaultConsoleURL,
		CredentialStore: CredentialStoreKeyring,
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(paths.Config)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Errorf("mode = %03o, want %03o", got, want)
	}
}

func TestLoadRejectsUnsafeURL(t *testing.T) {
	paths := Paths{Config: filepath.Join(t.TempDir(), "missing.toml")}
	_, err := Load(paths, Overrides{ControlURL: "https://user:secret@example.com"})
	if err == nil {
		t.Fatal("Load() error = nil, want URL validation error")
	}
}
