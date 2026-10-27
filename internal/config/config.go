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

	"github.com/pelletier/go-toml/v2"
	"github.com/scopedb/scopedb-cli/internal/fileutil"
)

const (
	DefaultControlURL = "https://control.scopedb.cloud"
	DefaultConsoleURL = "https://console.scopedb.cloud"
)

// Paths contains all local files owned by the CLI.
type Paths struct {
	Directory       string
	Config          string
	CredentialsFile string
	LockFile        string
}

// Config contains non-secret user configuration.
type Config struct {
	ControlURL           string                `toml:"control_url,omitempty"`
	ConsoleURL           string                `toml:"console_url,omitempty"`
	DefaultConnection    string                `toml:"default_connection,omitempty"`
	Connections          map[string]Connection `toml:"connections,omitempty"`
	LegacyProfiles       map[string]Connection `toml:"profiles,omitempty"`
	LegacyCurrentProfile string                `toml:"current_profile,omitempty"`
	ConnectionName       string                `toml:"-"`
	SelectedConnection   Connection            `toml:"-"`
	ConnectionExists     bool                  `toml:"-"`
	Temporary            bool                  `toml:"-"`
}

// Overrides contains explicit command-line overrides. Empty fields are ignored.
type Overrides struct {
	Connection  string
	AllowCreate bool
	ControlURL  string
	ConsoleURL  string
}

// ResolvePaths returns the platform-native configuration paths.
func ResolvePaths() (Paths, error) {
	directory := strings.TrimSpace(os.Getenv("SCOPEDB_HOME"))
	if directory == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve user config directory: %w", err)
		}
		directory = filepath.Join(base, "scopedb")
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return Paths{}, fmt.Errorf("resolve config directory: %w", err)
	}
	return Paths{
		Directory:       directory,
		Config:          filepath.Join(directory, "config.toml"),
		CredentialsFile: filepath.Join(directory, "credentials.json"),
		LockFile:        filepath.Join(directory, "credentials.lock"),
	}, nil
}

// Read reads saved configuration without command or environment overrides.
func Read(paths Paths) (Config, error) {
	cfg := Config{ControlURL: DefaultControlURL, ConsoleURL: DefaultConsoleURL}
	data, err := os.ReadFile(paths.Config)
	if err == nil {
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("read config %s: %w", paths.Config, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("read config %s: %w", paths.Config, err)
	}
	if err := validate(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Load selects a connection and applies environment and command-line service overrides.
func Load(paths Paths, overrides Overrides) (Config, error) {
	cfg, err := Read(paths)
	if err != nil {
		return Config{}, err
	}
	name := overrides.Connection
	if name == "" {
		name = cfg.DefaultConnection
	}
	if name == "" {
		if len(cfg.Connections) != 0 {
			return Config{}, fmt.Errorf("%w: no default is selected; run 'scope connection set-default <name>'", ErrUnknownConnection)
		}
		name = "default"
	}
	if err := ValidateConnectionName(name); err != nil {
		return Config{}, err
	}
	connection, exists := cfg.Connections[name]
	if !exists && !overrides.AllowCreate && (overrides.Connection != "" || len(cfg.Connections) != 0) {
		return Config{}, fmt.Errorf("%w: %q", ErrUnknownConnection, name)
	}
	if exists && connection.AuthType == AuthAPIKey {
		cfg.ConnectionName, cfg.SelectedConnection, cfg.ConnectionExists = name, connection, true
		return cfg, nil
	}
	if exists {
		cfg.ControlURL, cfg.ConsoleURL = connection.ControlURL, connection.ConsoleURL
	} else if current, ok := cfg.Connections[cfg.DefaultConnection]; ok && current.AuthType == AuthOAuth {
		cfg.ControlURL, cfg.ConsoleURL = current.ControlURL, current.ConsoleURL
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
	if exists && cfg.ControlURL != connection.ControlURL {
		return Config{}, fmt.Errorf("connection %q is bound to %s; use another connection for a different service", name, connection.ControlURL)
	}
	connection.AuthType = AuthOAuth
	connection.ControlURL, connection.ConsoleURL = cfg.ControlURL, cfg.ConsoleURL
	cfg.ConnectionName, cfg.SelectedConnection, cfg.ConnectionExists = name, connection, exists
	return cfg, nil
}

func applyEnv(cfg *Config) {
	if value := strings.TrimSpace(os.Getenv("SCOPEDB_CONTROL_URL")); value != "" {
		cfg.ControlURL = value
	}
	if value := strings.TrimSpace(os.Getenv("SCOPEDB_CONSOLE_URL")); value != "" {
		cfg.ConsoleURL = value
	}
}

func validate(cfg *Config) error {
	if len(cfg.LegacyProfiles) != 0 {
		if len(cfg.Connections) != 0 {
			return errors.New("configuration contains both profiles and connections")
		}
		cfg.Connections, cfg.DefaultConnection = cfg.LegacyProfiles, cfg.LegacyCurrentProfile
		cfg.LegacyProfiles, cfg.LegacyCurrentProfile = nil, ""
	}
	for name, connection := range cfg.Connections {
		if err := ValidateConnectionName(name); err != nil {
			return err
		}
		var err error
		if connection.AuthType == "" {
			connection.AuthType = AuthOAuth
		}
		switch connection.AuthType {
		case AuthAPIKey:
			connection.Endpoint, err = NormalizeEndpoint(connection.Endpoint)
			if err != nil {
				return fmt.Errorf("connection %q: invalid endpoint", name)
			}
			if connection.ControlURL != "" || connection.ConsoleURL != "" || connection.WorkspaceID != "" {
				return fmt.Errorf("API key connection %q requires an endpoint instead of OAuth service or workspace settings", name)
			}
			cfg.Connections[name] = connection
			continue
		case AuthOAuth:
			if connection.Endpoint != "" || connection.APIKeyEnv != "" {
				return fmt.Errorf("OAuth connection %q cannot specify endpoint or api_key_env", name)
			}
		default:
			return fmt.Errorf("connection %q: unknown authentication type %q", name, connection.AuthType)
		}
		if connection.ControlURL, err = normalizeBaseURL(connection.ControlURL); err != nil {
			return fmt.Errorf("connection %q: invalid control URL: %w", name, err)
		}
		if connection.ConsoleURL, err = normalizeBaseURL(connection.ConsoleURL); err != nil {
			return fmt.Errorf("connection %q: invalid console URL: %w", name, err)
		}
		cfg.Connections[name] = connection
	}
	if cfg.DefaultConnection != "" {
		if _, ok := cfg.Connections[cfg.DefaultConnection]; !ok {
			return fmt.Errorf("%w: current connection %q", ErrUnknownConnection, cfg.DefaultConnection)
		}
	}
	var err error
	if cfg.ControlURL, err = normalizeBaseURL(cfg.ControlURL); err != nil {
		return fmt.Errorf("invalid control URL: %w", err)
	}
	if cfg.ConsoleURL, err = normalizeBaseURL(cfg.ConsoleURL); err != nil {
		return fmt.Errorf("invalid console URL: %w", err)
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
	if len(cfg.Connections) != 0 {
		cfg.ControlURL, cfg.ConsoleURL = "", ""
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
	if err := fileutil.Commit(temporaryPath, path); err != nil {
		return fmt.Errorf("replace config file: %w", err)
	}
	return nil
}
