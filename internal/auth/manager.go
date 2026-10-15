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
	"github.com/scopedb/scopedb-cli/internal/filelock"
)

var (
	ErrNotLoggedIn         = errors.New("not logged in")
	ErrInvalidMachineEnv   = errors.New("invalid machine credentials")
	ErrApprovalRequired    = errors.New("account is awaiting approval")
	ErrNoWorkspaces        = errors.New("account has no workspaces")
	ErrNoWorkspaceSelected = errors.New("no workspace is selected")
	ErrLoginExpired        = errors.New("login is no longer valid")
)

const (
	// accessRefreshAhead renews an access token before it expires, so a command never starts with
	// a credential that dies mid-flight.
	accessRefreshAhead = 60 * time.Second

	// refreshRetryWindow and refreshRetryLimit bound retries of the same refresh token after a
	// transport failure or an HTTP 5xx, which is how a lost response is recovered while the
	// server's retry window is still open.
	refreshRetryWindow = 60 * time.Second
	refreshRetryLimit  = 2
	refreshRetryDelay  = time.Second
)

// ControlPlane is the account API reachable with an OAuth access token.
type ControlPlane interface {
	GetUser(context.Context, string) (controlplane.User, error)
	ListWorkspaces(context.Context, string) ([]controlplane.Workspace, error)
	GetWorkspace(context.Context, string, string) (controlplane.WorkspaceDetails, error)
	ExchangeToken(context.Context, string, string) (controlplane.TokenExchangeResponse, error)
}

// OAuthClient is the token-endpoint subset the CLI uses after login.
type OAuthClient interface {
	RefreshToken(context.Context, string) (controlplane.TokenSet, error)
	RevokeToken(context.Context, string) error
}

// Manager resolves machine credentials, the OAuth login, and short-lived data-plane credentials.
type Manager struct {
	ControlURL  string
	Control     ControlPlane
	OAuth       OAuthClient
	Credentials credential.Store
	LockFile    string
	Now         func() time.Time
	Sleep       func(time.Duration)
	Getenv      func(string) string
}

// Access contains everything needed to connect to the data plane.
type Access struct {
	Endpoint    string
	APIKey      string
	WorkspaceID string
	Mode        string
}

// Account is the signed-in user with the workspaces it owns and the locally selected one.
type Account struct {
	User                controlplane.User
	Workspaces          []controlplane.Workspace
	SelectedWorkspaceID string
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Manager) sleep(duration time.Duration) {
	if m.Sleep != nil {
		m.Sleep(duration)
		return
	}
	time.Sleep(duration)
}

func (m *Manager) getenv(name string) string {
	if m.Getenv != nil {
		return m.Getenv(name)
	}
	return os.Getenv(name)
}

// MachineAccess returns explicitly configured non-interactive credentials.
// A partial environment is rejected instead of falling through to a human login.
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

// LoadAccess returns stored credentials whose access token is valid now, refreshing the login when
// the token is missing, expired, or about to expire.
func (m *Manager) LoadAccess(ctx context.Context) (credential.State, error) {
	state, err := m.load()
	if err != nil {
		return credential.State{}, err
	}
	if state.AccessTokenExpiresAt.After(m.now().Add(accessRefreshAhead)) {
		return state, nil
	}
	return m.refresh(ctx, state)
}

func (m *Manager) load() (credential.State, error) {
	state, err := m.Credentials.Load(m.ControlURL)
	if errors.Is(err, credential.ErrNotFound) || errors.Is(err, credential.ErrInvalidState) {
		return credential.State{}, ErrNotLoggedIn
	}
	if err != nil {
		return credential.State{}, err
	}
	return state, nil
}

// SaveLogin persists the token pair a completed login issued and clears cached data credentials.
func (m *Manager) SaveLogin(tokens controlplane.TokenSet) error {
	state, err := m.tokenState(credential.State{}, tokens)
	if err != nil {
		return err
	}
	return m.Credentials.Save(m.ControlURL, state)
}

// Account loads the signed-in user, the owned workspaces, and the locally selected workspace.
func (m *Manager) Account(ctx context.Context) (Account, error) {
	account, _, err := m.account(ctx)
	return account, err
}

func (m *Manager) account(ctx context.Context) (Account, credential.State, error) {
	state, err := m.LoadAccess(ctx)
	if err != nil {
		return Account{}, credential.State{}, err
	}
	user, err := m.Control.GetUser(ctx, state.AccessToken)
	if err != nil {
		return Account{}, credential.State{}, err
	}
	workspaces, err := m.Control.ListWorkspaces(ctx, state.AccessToken)
	if err != nil {
		return Account{}, credential.State{}, err
	}
	return Account{User: user, Workspaces: workspaces, SelectedWorkspaceID: state.WorkspaceID}, state, nil
}

// SelectWorkspace stores the workspace this profile uses. An OAuth credential is never rotated to
// change workspace, so the selection is local state.
func (m *Manager) SelectWorkspace(ctx context.Context, workspaceID string) error {
	state, err := m.LoadAccess(ctx)
	if err != nil {
		return err
	}
	if state.WorkspaceID == workspaceID {
		return nil
	}
	state.WorkspaceID = workspaceID
	state.DataToken = ""
	state.DataTokenWorkspaceID = ""
	state.DataTokenExpiresAt = time.Time{}
	if err := m.Credentials.Save(m.ControlURL, state); err != nil {
		return fmt.Errorf("workspace changed, but the selection could not be saved: %w", err)
	}
	return nil
}

// LogoutCleanupError reports a completed local logout whose remote revocation failed. The login
// stays usable until it expires or the user revokes it in the Console.
type LogoutCleanupError struct{ Err error }

func (e *LogoutCleanupError) Error() string {
	return fmt.Sprintf("local credentials removed, but the login could not be revoked: %s", e.Err)
}

func (e *LogoutCleanupError) Unwrap() error { return e.Err }

// Logout revokes the stored login and removes local credentials. Local credentials are removed even
// when revocation fails, and the failure is reported so the user knows the login may still exist.
func (m *Manager) Logout(ctx context.Context) error {
	state, err := m.Credentials.Load(m.ControlURL)
	if errors.Is(err, credential.ErrInvalidState) {
		return m.deleteIgnoringMissing()
	}
	if errors.Is(err, credential.ErrNotFound) {
		return ErrNotLoggedIn
	}
	if err != nil {
		return err
	}

	token := state.RefreshToken
	if token == "" {
		token = state.AccessToken
	}
	revokeErr := m.OAuth.RevokeToken(ctx, token)
	if err := m.deleteIgnoringMissing(); err != nil {
		return fmt.Errorf("remove local credentials: %w", errors.Join(revokeErr, err))
	}
	if revokeErr != nil {
		return &LogoutCleanupError{Err: revokeErr}
	}
	return nil
}

func (m *Manager) deleteIgnoringMissing() error {
	if err := m.Credentials.Delete(m.ControlURL); err != nil && !errors.Is(err, credential.ErrNotFound) {
		return err
	}
	return nil
}

// ResolveDataAccess returns machine credentials when configured, otherwise it exchanges the OAuth
// login for a short-lived data-plane credential.
func (m *Manager) ResolveDataAccess(ctx context.Context) (Access, error) {
	if access, active, err := m.MachineAccess(); active || err != nil {
		return access, err
	}

	account, state, err := m.account(ctx)
	if err != nil {
		return Access{}, err
	}
	if err := RequireWorkspace(account); err != nil {
		return Access{}, err
	}
	details, err := m.Control.GetWorkspace(ctx, state.AccessToken, state.WorkspaceID)
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
			Mode:        "oauth",
		}, nil
	}

	exchanged, err := m.Control.ExchangeToken(ctx, state.AccessToken, state.WorkspaceID)
	if err != nil {
		return Access{}, err
	}
	if !strings.EqualFold(exchanged.TokenType, "Bearer") || exchanged.AccessToken == "" || exchanged.ExpiresAt.IsZero() {
		return Access{}, fmt.Errorf("token exchange returned an invalid credential")
	}
	state.DataToken = exchanged.AccessToken
	state.DataTokenWorkspaceID = state.WorkspaceID
	state.DataTokenExpiresAt = exchanged.ExpiresAt.UTC()
	if err := m.Credentials.Save(m.ControlURL, state); err != nil {
		return Access{}, fmt.Errorf("save short-lived data credential: %w", err)
	}
	return Access{
		Endpoint:    details.Connection.APIBaseURL,
		APIKey:      exchanged.AccessToken,
		WorkspaceID: state.WorkspaceID,
		Mode:        "oauth",
	}, nil
}

// RequireWorkspace reports what prevents an account from accessing a workspace.
func RequireWorkspace(account Account) error {
	if account.User.Status == "pending" {
		return ErrApprovalRequired
	}
	if account.SelectedWorkspaceID == "" {
		if len(account.Workspaces) == 0 {
			return ErrNoWorkspaces
		}
		return ErrNoWorkspaceSelected
	}
	return nil
}

// refresh rotates the stored refresh token under an exclusive file lock, because several CLI
// processes share one credential store and rotation is single use. The server serves the token a
// rotation consumed again for a minute, which covers one process retrying a lost response, not
// unsynchronized processes.
func (m *Manager) refresh(ctx context.Context, state credential.State) (credential.State, error) {
	lock, err := filelock.Acquire(ctx, m.LockFile)
	if err != nil {
		return credential.State{}, err
	}
	defer func() { _ = lock.Close() }()

	// Another process may have refreshed the login while this one waited for the lock.
	current, loadErr := m.Credentials.Load(m.ControlURL)
	switch {
	case loadErr == nil && current.AccessToken != state.AccessToken && current.AccessTokenExpiresAt.After(m.now().Add(accessRefreshAhead)):
		return current, nil
	case loadErr == nil:
		state = current
	case errors.Is(loadErr, credential.ErrNotFound), errors.Is(loadErr, credential.ErrInvalidState):
		// Another process logged out or replaced the login.
		return credential.State{}, ErrNotLoggedIn
	default:
		return credential.State{}, loadErr
	}

	deadline := m.now().Add(refreshRetryWindow)
	for attempt := 0; ; attempt++ {
		tokens, refreshErr := m.OAuth.RefreshToken(ctx, state.RefreshToken)
		if refreshErr == nil {
			updated, err := m.tokenState(state, tokens)
			if err != nil {
				return credential.State{}, err
			}
			if err := m.Credentials.Save(m.ControlURL, updated); err != nil {
				return credential.State{}, fmt.Errorf("save refreshed credentials: %w", err)
			}
			return updated, nil
		}
		if ctx.Err() != nil {
			return credential.State{}, ctx.Err()
		}
		if isInvalidGrant(refreshErr) {
			// The reuse-detection and idle-expiry rules end the whole grant, so the stored
			// credentials can never work again.
			_ = m.Credentials.Delete(m.ControlURL)
			return credential.State{}, fmt.Errorf("%w: %s; run 'scope auth login'", ErrLoginExpired, refreshErr)
		}
		if attempt < refreshRetryLimit && m.now().Before(deadline) && retryableRefresh(refreshErr) {
			m.sleep(refreshRetryDelay)
			continue
		}
		return credential.State{}, refreshErr
	}
}

func (m *Manager) tokenState(state credential.State, tokens controlplane.TokenSet) (credential.State, error) {
	if tokens.AccessToken == "" || tokens.ExpiresIn <= 0 {
		return credential.State{}, fmt.Errorf("ScopeDB returned an incomplete token response")
	}
	if tokens.RefreshToken == "" {
		return credential.State{}, fmt.Errorf("ScopeDB returned no refresh token")
	}
	now := m.now()
	state.AccessToken = tokens.AccessToken
	state.AccessTokenExpiresAt = now.Add(time.Duration(tokens.ExpiresIn) * time.Second)
	state.RefreshToken = tokens.RefreshToken
	state.RefreshTokenExpiresAt = time.Time{}
	if tokens.RefreshTokenExpiresIn > 0 {
		state.RefreshTokenExpiresAt = now.Add(time.Duration(tokens.RefreshTokenExpiresIn) * time.Second)
	}
	return state, nil
}

func isInvalidGrant(err error) bool {
	var protocol *controlplane.OAuthError
	return errors.As(err, &protocol) && protocol.Code == "invalid_grant"
}

// retryableRefresh reports whether presenting the same refresh token again is safe. A transport
// failure or an HTTP 5xx may mean the response was lost; a 429 must not be retried.
func retryableRefresh(err error) bool {
	var protocol *controlplane.OAuthError
	if !errors.As(err, &protocol) {
		return false
	}
	if protocol.Status == 0 {
		return true
	}
	return protocol.Status >= 500
}
