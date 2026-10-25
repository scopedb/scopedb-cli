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

// Version 1 held a browser session token that an OAuth login can never use, so an older document is
// invalid rather than migrated.
const currentStateVersion = 3

const (
	SourceKeyring   = "keyring"
	SourcePlaintext = "plaintext"
)

var ErrNotFound = errors.New("credentials not found")

// ErrInvalidState identifies an unusable profile that Save can replace. It does
// not cover storage access failures or unreadable multi-profile documents.
var ErrInvalidState = errors.New("stored credential state is invalid")

type State struct {
	CredentialID string `json:"credential_id,omitempty"`
	LoginID      string `json:"login_id,omitempty"`
	// MigratedTo claims a legacy record before moving it, so interrupted migrations
	// resume only for the owning profile and never duplicate rotating credentials.
	MigratedTo string `json:"migrated_to,omitempty"`
	// Source is resolved on load, never persisted. Updates keep this destination;
	// a new login has no source and chooses its destination independently.
	Source string `json:"-"`
	// Cleared suppresses an inaccessible keyring entry after local logout. A
	// plaintext tombstone contains no tokens and is replaced by the next login.
	Cleared               bool      `json:"cleared,omitempty"`
	Version               int       `json:"version"`
	ControlURL            string    `json:"control_url"`
	AccessToken           string    `json:"access_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshToken          string    `json:"refresh_token"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	WorkspaceID           string    `json:"workspace_id,omitempty"`
	DataToken             string    `json:"data_token,omitempty"`
	DataTokenWorkspaceID  string    `json:"data_token_workspace_id,omitempty"`
	DataTokenExpiresAt    time.Time `json:"data_token_expires_at,omitempty"`
}

// Store persists credentials for a bound profile, validating its control-plane origin.
type Store interface {
	Load(controlURL string) (State, error)
	Save(controlURL string, state State) error
	Delete(controlURL string) error
}

// New returns one credential backend without accessing it.
func New(kind string, paths config.Paths, reference string) (Store, error) {
	switch kind {
	case SourceKeyring:
		return NewKeyringStore(reference), nil
	case SourcePlaintext:
		return NewPlaintextStore(paths.CredentialsFile, reference), nil
	default:
		return nil, fmt.Errorf("unsupported credential store %q", kind)
	}
}

func prepare(controlURL, reference string, state State) State {
	state.Version = currentStateVersion
	state.CredentialID = reference
	state.ControlURL = controlURL
	return state
}

func validate(controlURL, reference string, state State) error {
	if state.Version != currentStateVersion && (reference != "" || state.Version != 2) {
		return fmt.Errorf("%w: unsupported version %d; log in again", ErrInvalidState, state.Version)
	}
	if state.ControlURL != controlURL || state.CredentialID != reference {
		return fmt.Errorf("%w: credential origin mismatch", ErrInvalidState)
	}
	if state.Cleared && state.AccessToken == "" && state.RefreshToken == "" && state.DataToken == "" {
		return nil
	}
	if state.AccessToken == "" {
		return fmt.Errorf("%w: access token is missing", ErrInvalidState)
	}
	if state.RefreshToken == "" {
		return fmt.Errorf("%w: refresh token is missing", ErrInvalidState)
	}
	return nil
}

func profileKey(controlURL, reference string) string {
	if reference != "" {
		controlURL += "\x00" + reference
	}
	digest := sha256.Sum256([]byte(controlURL))
	return hex.EncodeToString(digest[:])
}
