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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/scopedb/scopedb-cli/internal/config"
)

const currentStateVersion = 1

var ErrNotFound = errors.New("credentials not found")

// State contains secrets and their workspace binding. It must never be written
// to the regular TOML configuration file.
type State struct {
	Version              int       `json:"version"`
	ControlURL           string    `json:"control_url"`
	SessionToken         string    `json:"session_token"`
	WorkspaceID          string    `json:"workspace_id"`
	DataToken            string    `json:"data_token,omitempty"`
	DataTokenWorkspaceID string    `json:"data_token_workspace_id,omitempty"`
	DataTokenExpiresAt   time.Time `json:"data_token_expires_at,omitempty"`
}

// Store persists credentials for one or more control-plane origins.
type Store interface {
	Load(controlURL string) (State, error)
	Save(controlURL string, state State) error
	Delete(controlURL string) error
}

// New returns the configured credential backend. Plaintext storage must be an
// explicit user choice; there is no automatic downgrade from the OS keyring.
func New(kind string, paths config.Paths) (Store, error) {
	switch kind {
	case config.CredentialStoreKeyring:
		return NewKeyringStore(), nil
	case config.CredentialStorePlaintext:
		return NewPlaintextStore(paths.CredentialsFile), nil
	default:
		return nil, fmt.Errorf("unsupported credential store %q", kind)
	}
}

func prepare(controlURL string, state State) State {
	state.Version = currentStateVersion
	state.ControlURL = controlURL
	return state
}

func validate(controlURL string, state State) error {
	if state.Version != currentStateVersion {
		return fmt.Errorf("unsupported credential state version %d", state.Version)
	}
	if state.ControlURL != controlURL {
		return fmt.Errorf("credential origin mismatch")
	}
	if state.SessionToken == "" || state.WorkspaceID == "" {
		return fmt.Errorf("credential state is incomplete")
	}
	return nil
}

func profileKey(controlURL string) string {
	digest := sha256.Sum256([]byte(controlURL))
	return hex.EncodeToString(digest[:])
}
