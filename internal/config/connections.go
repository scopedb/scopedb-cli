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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

var ErrUnknownConnection = errors.New("unknown connection")

const (
	AuthOAuth  = "oauth"
	AuthAPIKey = "api_key"
)

// Connection stores defaults and last known identity information, never credentials.
type Connection struct {
	AuthType      string `toml:"auth_type" json:"auth_type"`
	Endpoint      string `toml:"endpoint,omitempty" json:"endpoint,omitempty"`
	APIKeyEnv     string `toml:"api_key_env,omitempty" json:"api_key_env,omitempty"`
	ControlURL    string `toml:"control_url,omitempty" json:"control_url,omitempty"`
	ConsoleURL    string `toml:"console_url,omitempty" json:"console_url,omitempty"`
	WorkspaceID   string `toml:"workspace_id,omitempty" json:"workspace_id,omitempty"`
	WorkspaceName string `toml:"workspace_name,omitempty" json:"workspace_name,omitempty"`
	UserID        string `toml:"last_user_id,omitempty" json:"last_user_id,omitempty"`
	Email         string `toml:"last_email,omitempty" json:"last_email,omitempty"`
}

func (c Connection) CredentialOrigin() string {
	if c.AuthType == AuthAPIKey {
		return c.Endpoint
	}
	return c.ControlURL
}

// NormalizeEndpoint rejects URL components that could hide credentials or alter routing.
func NormalizeEndpoint(value string) (string, error) { return normalizeBaseURL(value) }

func ValidateConnectionName(name string) error {
	if name == "" || len(name) > 64 || strings.IndexFunc(name, func(r rune) bool {
		valid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.'
		return !valid
	}) != -1 {
		return fmt.Errorf("connection names must contain 1 to 64 letters, digits, dots, underscores, or hyphens")
	}
	return nil
}

// CredentialReference isolates equal connection names in different configuration directories.
func CredentialReference(paths Paths, name string) string {
	directory := paths.Directory
	// Resolve existing parent symlinks even before a new config directory is created.
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(directory)
		if err == nil {
			directory = filepath.Join(append([]string{resolved}, suffix...)...)
			break
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			directory = paths.Directory
			break
		}
		suffix = append([]string{filepath.Base(directory)}, suffix...)
		directory = parent
	}
	digest := sha256.Sum256([]byte(directory + "\x00" + name))
	return hex.EncodeToString(digest[:])
}

// SaveConnection merges one connection into the latest document. The caller holds Paths.LockFile.
func SaveConnection(paths Paths, name string, connection Connection, establishDefault bool) error {
	cfg, err := Read(paths)
	if err != nil {
		return err
	}
	if cfg.Connections == nil {
		cfg.Connections = map[string]Connection{}
	}
	if existing, ok := cfg.Connections[name]; ok && existing.ControlURL != connection.ControlURL {
		return fmt.Errorf("connection %q changed service while the command was running", name)
	}
	cfg.Connections[name] = connection
	if establishDefault && cfg.DefaultConnection == "" {
		cfg.DefaultConnection = name
	}
	return Save(paths, cfg)
}
