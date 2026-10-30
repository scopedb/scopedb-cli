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
const currentStateVersion = 2

const (
	SourceKeyring   = "keyring"
	SourcePlaintext = "plaintext"
)

const (
	// KindOAuth is an interactive login with access and refresh tokens.
	KindOAuth = "oauth"
	// KindWorkload is a non-renewable CI login holding a workspace-bound
	// data-plane credential obtained through the workload identity exchange.
	KindWorkload = "workload"
)

var ErrNotFound = errors.New("credentials not found")

// ErrInvalidState identifies an unusable profile that Save can replace. It does
// not cover storage access failures or unreadable multi-profile documents.
var ErrInvalidState = errors.New("stored credential state is invalid")

type State struct {
	// Source is resolved on load, never persisted. Updates keep this destination;
	// a new login has no source and chooses its destination independently.
	Source string `json:"-"`
	// Cleared suppresses an inaccessible keyring entry after local logout. A
	// plaintext tombstone contains no tokens and is replaced by the next login.
	Cleared    bool   `json:"cleared,omitempty"`
	Version    int    `json:"version"`
	ControlURL string `json:"control_url"`
	// Kind selects the credential shape. An empty kind is an OAuth login written
	// before kinds existed, so it validates like KindOAuth.
	Kind                  string    `json:"kind,omitempty"`
	AccessToken           string    `json:"access_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshToken          string    `json:"refresh_token"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	WorkspaceID           string    `json:"workspace_id,omitempty"`
	DataToken             string    `json:"data_token,omitempty"`
	DataTokenWorkspaceID  string    `json:"data_token_workspace_id,omitempty"`
	DataTokenExpiresAt    time.Time `json:"data_token_expires_at,omitempty"`
	// KindWorkload fields: the bound workspace's data-plane credential and the
	// policy that issued it, kept for display. There is nothing to refresh.
	Endpoint        string            `json:"endpoint,omitempty"`
	APIKey          string            `json:"api_key,omitempty"`
	APIKeyExpiresAt time.Time         `json:"api_key_expires_at,omitempty"`
	Workload        *WorkloadIdentity `json:"workload,omitempty"`
}

// WorkloadIdentity describes the CI trust policy that issued a workload
// credential. It is descriptive only; authorization used the exact subject.
type WorkloadIdentity struct {
	PolicyID string `json:"policy_id,omitempty"`
	Name     string `json:"name,omitempty"`
	Provider string `json:"provider,omitempty"`
	Subject  string `json:"subject,omitempty"`
}

// Store persists credentials for one or more control-plane origins.
type Store interface {
	Load(controlURL string) (State, error)
	Save(controlURL string, state State) error
	Delete(controlURL string) error
}

// New returns one credential backend without accessing it.
func New(kind string, paths config.Paths) (Store, error) {
	switch kind {
	case SourceKeyring:
		return NewKeyringStore(), nil
	case SourcePlaintext:
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
		return fmt.Errorf("%w: unsupported version %d; log in again", ErrInvalidState, state.Version)
	}
	if state.ControlURL != controlURL {
		return fmt.Errorf("%w: credential origin mismatch", ErrInvalidState)
	}
	if state.Cleared && state.AccessToken == "" && state.RefreshToken == "" && state.DataToken == "" && state.APIKey == "" {
		return nil
	}
	switch state.Kind {
	case "", KindOAuth:
		if state.AccessToken == "" {
			return fmt.Errorf("%w: access token is missing", ErrInvalidState)
		}
		if state.RefreshToken == "" {
			return fmt.Errorf("%w: refresh token is missing", ErrInvalidState)
		}
		return nil
	case KindWorkload:
		// A workload credential never holds a refresh token; the API key is its
		// access credential and cannot resolve access without its binding.
		if state.APIKey == "" {
			return fmt.Errorf("%w: workload API key is missing", ErrInvalidState)
		}
		if state.Endpoint == "" || state.WorkspaceID == "" {
			return fmt.Errorf("%w: workload workspace binding is incomplete", ErrInvalidState)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported credential kind %q", ErrInvalidState, state.Kind)
	}
}

func profileKey(controlURL string) string {
	digest := sha256.Sum256([]byte(controlURL))
	return hex.EncodeToString(digest[:])
}
