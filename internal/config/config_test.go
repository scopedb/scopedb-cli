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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, Save(paths, fileConfig))

	t.Setenv("SCOPEDB_CONTROL_URL", "https://env-control.example.com/")
	t.Setenv("SCOPEDB_CONSOLE_URL", "https://env-console.example.com/")
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", CredentialStoreKeyring)
	cfg, err := Load(paths, Overrides{ControlURL: "https://flag-control.example.com/"})
	require.NoError(t, err)
	assert.Equal(t, "https://flag-control.example.com", cfg.ControlURL)
	assert.Equal(t, "https://env-console.example.com", cfg.ConsoleURL)
	assert.Equal(t, CredentialStoreKeyring, cfg.CredentialStore)
}

func TestLoadExistingConfig(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.toml")
	contents := []byte(`control_url = "https://control.example.com"
console_url = "https://console.example.com"
credential_store = "plaintext"
`)
	require.NoError(t, os.WriteFile(path, contents, 0o600))
	t.Setenv("SCOPEDB_CONTROL_URL", "")
	t.Setenv("SCOPEDB_CONSOLE_URL", "")
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", "")
	cfg, err := Load(Paths{Directory: directory, Config: path}, Overrides{})
	require.NoError(t, err)
	assert.Equal(t, "https://control.example.com", cfg.ControlURL)
	assert.Equal(t, "https://console.example.com", cfg.ConsoleURL)
	assert.Equal(t, CredentialStorePlaintext, cfg.CredentialStore)
}

func TestResolvePathsUsesOverride(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "nested")
	t.Setenv("SCOPEDB_CONFIG_DIR", directory)
	paths, err := ResolvePaths()
	require.NoError(t, err)
	assert.Equal(t, directory, paths.Directory)
	assert.Equal(t, filepath.Join(directory, "config.toml"), paths.Config)
}

func TestResolvePathsUsesPlatformConfigDirectory(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", "")
	base, err := os.UserConfigDir()
	require.NoError(t, err)
	paths, err := ResolvePaths()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, "scopedb"), paths.Directory)
}

func TestSaveRestrictsPermissions(t *testing.T) {
	directory := t.TempDir()
	paths := Paths{Directory: directory, Config: filepath.Join(directory, "config.toml")}
	require.NoError(t, Save(paths, Config{
		ControlURL:      DefaultControlURL,
		ConsoleURL:      DefaultConsoleURL,
		CredentialStore: CredentialStoreKeyring,
	}))
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(paths.Config)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestLoadRejectsUnsafeURL(t *testing.T) {
	paths := Paths{Config: filepath.Join(t.TempDir(), "missing.toml")}
	_, err := Load(paths, Overrides{ControlURL: "https://user:secret@example.com"})
	assert.Error(t, err)
}
