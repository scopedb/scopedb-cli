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
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/scopedb/scopedb-cli/internal/fileutil"
)

const (
	DefaultControlURL = "https://control.scopedb.cloud"
	DefaultConsoleURL = "https://console.scopedb.cloud"

	CredentialStoreKeyring   = "keyring"
	CredentialStorePlaintext = "plaintext"
)

// Paths contains all local files owned by the CLI.
type Paths struct {
	Directory       string
	Config          string
	CredentialsFile string
}

// Config contains non-secret user configuration.
type Config struct {
	ControlURL      string `toml:"control_url,omitempty"`
	ConsoleURL      string `toml:"console_url,omitempty"`
	CredentialStore string `toml:"credential_store,omitempty"`
}

// Overrides contains explicit command-line overrides. Empty fields are ignored.
type Overrides struct {
	ControlURL string
	ConsoleURL string
}

// ResolvePaths returns the platform-native configuration paths.
func ResolvePaths() (Paths, error) {
	directory := strings.TrimSpace(os.Getenv("SCOPEDB_CONFIG_DIR"))
	if directory == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve user config directory: %w", err)
		}
		directory = filepath.Join(base, "scopedb", "cli")
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return Paths{}, fmt.Errorf("resolve config directory: %w", err)
	}
	return Paths{
		Directory:       directory,
		Config:          filepath.Join(directory, "config.toml"),
		CredentialsFile: filepath.Join(directory, "credentials.json"),
	}, nil
}

// Load resolves configuration in increasing precedence: defaults, file,
// environment, and explicit command-line overrides.
func Load(paths Paths, overrides Overrides) (Config, error) {
	cfg := Config{
		ControlURL:      DefaultControlURL,
		ConsoleURL:      DefaultConsoleURL,
		CredentialStore: CredentialStoreKeyring,
	}

	if _, err := toml.DecodeFile(paths.Config, &cfg); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("read config %s: %w", paths.Config, err)
	}
	applyEnv(&cfg)
	if overrides.ControlURL != "" {
		cfg.ControlURL = overrides.ControlURL
	}
	if overrides.ConsoleURL != "" {
		cfg.ConsoleURL = overrides.ConsoleURL
	}
	if err := validate(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
	if value := strings.TrimSpace(os.Getenv("SCOPEDB_CONTROL_URL")); value != "" {
		cfg.ControlURL = value
	}
	if value := strings.TrimSpace(os.Getenv("SCOPEDB_CONSOLE_URL")); value != "" {
		cfg.ConsoleURL = value
	}
	if value := strings.TrimSpace(os.Getenv("SCOPEDB_CREDENTIAL_STORE")); value != "" {
		cfg.CredentialStore = value
	}
}

func validate(cfg *Config) error {
	var err error
	if cfg.ControlURL, err = normalizeBaseURL(cfg.ControlURL); err != nil {
		return fmt.Errorf("invalid control URL: %w", err)
	}
	if cfg.ConsoleURL, err = normalizeBaseURL(cfg.ConsoleURL); err != nil {
		return fmt.Errorf("invalid console URL: %w", err)
	}
	switch cfg.CredentialStore {
	case CredentialStoreKeyring, CredentialStorePlaintext:
	default:
		return fmt.Errorf("unsupported credential store %q", cfg.CredentialStore)
	}
	return nil
}

func normalizeBaseURL(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("scheme must be https or http")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("host is required")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("userinfo, query, and fragment are not allowed")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String(), nil
}

// Save persists non-secret configuration atomically.
func Save(paths Paths, cfg Config) error {
	if err := validate(&cfg); err != nil {
		return err
	}
	if err := os.MkdirAll(paths.Directory, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	data, err := toml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	return writeAtomic(paths.Config, data, 0o600)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".scope-config-*")
	if err != nil {
		return fmt.Errorf("create temporary config file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set temporary config permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary config file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary config file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary config file: %w", err)
	}
	if err := fileutil.Commit(temporaryPath, path, true); err != nil {
		return fmt.Errorf("replace config file: %w", err)
	}
	return nil
}
