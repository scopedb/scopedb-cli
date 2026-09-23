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

package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
)

var (
	ErrNotLoggedIn         = errors.New("not logged in")
	ErrInvalidMachineEnv   = errors.New("invalid machine credentials")
	ErrApprovalRequired    = errors.New("account is awaiting approval")
	ErrNoWorkspaces        = errors.New("account has no workspaces")
	ErrNoWorkspaceSelected = errors.New("no workspace is selected")
)

type controlClient interface {
	GetSession(context.Context, string) (controlplane.Session, error)
	GetWorkspace(context.Context, string, string) (controlplane.WorkspaceDetails, error)
	ExchangeToken(context.Context, string, string) (controlplane.TokenExchangeResponse, error)
	SelectWorkspace(context.Context, string, string) (controlplane.LoginResponse, error)
}

// Manager resolves human sessions and short-lived data-plane credentials.
type Manager struct {
	ControlURL  string
	Control     controlClient
	Credentials credential.Store
	Now         func() time.Time
	Getenv      func(string) string
}

// Access contains everything needed to connect to the data plane.
type Access struct {
	Endpoint    string
	APIKey      string
	WorkspaceID string
	Mode        string
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Manager) getenv(name string) string {
	if m.Getenv != nil {
		return m.Getenv(name)
	}
	return os.Getenv(name)
}

// MachineAccess returns explicitly configured non-interactive credentials.
// A partial environment is rejected instead of falling through to a human session.
func (m *Manager) MachineAccess() (Access, bool, error) {
	endpoint := strings.TrimSpace(m.getenv("SCOPEDB_ENDPOINT"))
	apiKey := strings.TrimSpace(m.getenv("SCOPEDB_API_KEY"))
	if endpoint == "" && apiKey == "" {
		return Access{}, false, nil
	}
	if endpoint == "" || apiKey == "" {
		return Access{}, false, fmt.Errorf("%w: SCOPEDB_ENDPOINT and SCOPEDB_API_KEY must be set together", ErrInvalidMachineEnv)
	}
	return Access{Endpoint: endpoint, APIKey: apiKey, Mode: "api_key"}, true, nil
}

// LoadSession loads and verifies the current human session.
func (m *Manager) LoadSession(ctx context.Context) (credential.State, controlplane.Session, error) {
	state, err := m.Credentials.Load(m.ControlURL)
	if errors.Is(err, credential.ErrNotFound) {
		return credential.State{}, controlplane.Session{}, ErrNotLoggedIn
	}
	if err != nil {
		return credential.State{}, controlplane.Session{}, err
	}
	session, err := m.Control.GetSession(ctx, state.SessionToken)
	if err != nil {
		return credential.State{}, controlplane.Session{}, err
	}
	if state.WorkspaceID != session.CurrentWorkspaceID {
		state.WorkspaceID = session.CurrentWorkspaceID
		state.DataToken = ""
		state.DataTokenWorkspaceID = ""
		state.DataTokenExpiresAt = time.Time{}
		if err := m.Credentials.Save(m.ControlURL, state); err != nil {
			return credential.State{}, controlplane.Session{}, fmt.Errorf("persist current workspace: %w", err)
		}
	}
	return state, session, nil
}

// LoadWorkspaceSession requires a selected workspace in addition to a valid session.
func (m *Manager) LoadWorkspaceSession(ctx context.Context) (credential.State, error) {
	state, session, err := m.LoadSession(ctx)
	if err != nil {
		return credential.State{}, err
	}
	if err := RequireWorkspace(session); err != nil {
		return credential.State{}, err
	}
	return state, nil
}

// RequireWorkspace reports what prevents a session from accessing a workspace.
func RequireWorkspace(session controlplane.Session) error {
	if session.User.Status == "pending" {
		return ErrApprovalRequired
	}
	if session.CurrentWorkspaceID == "" {
		if len(session.Workspaces) == 0 {
			return ErrNoWorkspaces
		}
		return ErrNoWorkspaceSelected
	}
	return nil
}

// SaveLogin persists a newly issued human session and clears cached data credentials.
func (m *Manager) SaveLogin(response controlplane.LoginResponse) error {
	if response.Token == "" {
		return fmt.Errorf("login response is incomplete")
	}
	return m.Credentials.Save(m.ControlURL, credential.State{
		SessionToken: response.Token,
		WorkspaceID:  response.WorkspaceID,
	})
}

// SelectWorkspace rotates the workspace-scoped human session and persists it.
func (m *Manager) SelectWorkspace(ctx context.Context, state credential.State, workspaceID string) error {
	response, err := m.Control.SelectWorkspace(ctx, state.SessionToken, workspaceID)
	if err != nil {
		return err
	}
	state.SessionToken = response.Token
	state.WorkspaceID = response.WorkspaceID
	state.DataToken = ""
	state.DataTokenWorkspaceID = ""
	state.DataTokenExpiresAt = time.Time{}
	if err := m.Credentials.Save(m.ControlURL, state); err != nil {
		return fmt.Errorf("workspace changed, but the rotated session could not be saved; log in again: %w", err)
	}
	return nil
}

// ResolveDataAccess returns machine credentials when configured, otherwise it
// exchanges the human session for a short-lived data-plane token.
func (m *Manager) ResolveDataAccess(ctx context.Context) (Access, error) {
	if access, active, err := m.MachineAccess(); active || err != nil {
		return access, err
	}

	state, err := m.LoadWorkspaceSession(ctx)
	if err != nil {
		return Access{}, err
	}
	return m.resolveDataAccess(ctx, state, true)
}

// ResolveDataAccessForWorkspace exchanges a token for a one-command workspace
// override without changing the saved session or data-token cache.
func (m *Manager) ResolveDataAccessForWorkspace(ctx context.Context, state credential.State) (Access, error) {
	if state.SessionToken == "" || state.WorkspaceID == "" {
		return Access{}, fmt.Errorf("workspace session is incomplete")
	}
	return m.resolveDataAccess(ctx, state, false)
}

func (m *Manager) resolveDataAccess(ctx context.Context, state credential.State, saveToken bool) (Access, error) {
	details, err := m.Control.GetWorkspace(ctx, state.SessionToken, state.WorkspaceID)
	if err != nil {
		return Access{}, err
	}
	if details.Provisioning.Status != "ready" {
		return Access{}, fmt.Errorf("workspace %s is %s", state.WorkspaceID, details.Provisioning.Status)
	}
	if details.Connection.APIBaseURL == "" {
		return Access{}, fmt.Errorf("workspace %s has no data-plane endpoint", state.WorkspaceID)
	}

	if state.DataToken != "" && state.DataTokenWorkspaceID == state.WorkspaceID && state.DataTokenExpiresAt.After(m.now().Add(30*time.Second)) {
		return Access{
			Endpoint:    details.Connection.APIBaseURL,
			APIKey:      state.DataToken,
			WorkspaceID: state.WorkspaceID,
			Mode:        "session",
		}, nil
	}

	exchanged, err := m.Control.ExchangeToken(ctx, state.SessionToken, state.WorkspaceID)
	if err != nil {
		return Access{}, err
	}
	if !strings.EqualFold(exchanged.TokenType, "Bearer") || exchanged.AccessToken == "" || exchanged.ExpiresAt.IsZero() {
		return Access{}, fmt.Errorf("token exchange returned an invalid credential")
	}
	state.DataToken = exchanged.AccessToken
	state.DataTokenWorkspaceID = state.WorkspaceID
	state.DataTokenExpiresAt = exchanged.ExpiresAt.UTC()
	if saveToken {
		if err := m.Credentials.Save(m.ControlURL, state); err != nil {
			return Access{}, fmt.Errorf("save short-lived data credential: %w", err)
		}
	}
	return Access{
		Endpoint:    details.Connection.APIBaseURL,
		APIKey:      exchanged.AccessToken,
		WorkspaceID: state.WorkspaceID,
		Mode:        "session",
	}, nil
}
