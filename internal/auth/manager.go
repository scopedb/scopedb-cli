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
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/scopedb/scopedb-cli/internal/filelock"
)

var (
	ErrNotLoggedIn           = errors.New("not logged in")
	ErrAlreadyLoggedIn       = errors.New("a renewable login is already stored")
	ErrInvalidMachineEnv     = errors.New("invalid machine credentials")
	ErrApprovalRequired      = errors.New("account is awaiting approval")
	ErrNoWorkspaces          = errors.New("account has no workspaces")
	ErrNoWorkspaceSelected   = errors.New("no workspace is selected")
	ErrWorkspaceUnavailable  = errors.New("selected workspace is no longer available")
	ErrLoginExpired          = errors.New("login is no longer valid")
	ErrCredentialsUnreadable = errors.New("existing credentials could not be read")
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

type ControlPlane interface {
	GetUser(context.Context, string) (controlplane.User, error)
	ListWorkspaces(context.Context, string) ([]controlplane.Workspace, error)
	GetWorkspace(context.Context, string, string) (controlplane.WorkspaceDetails, error)
	ExchangeToken(context.Context, string, string) (controlplane.TokenExchangeResponse, error)
}

type OAuthClient interface {
	RefreshToken(context.Context, string) (controlplane.TokenSet, error)
	RevokeToken(context.Context, string) error
}

// CredentialStore distinguishes updates to an existing login from replacing
// one. Replace chooses a new login's destination or restores a saved source.
type CredentialStore interface {
	credential.Store
	Replace(controlURL string, state credential.State) error
}

type Manager struct {
	ControlURL  string
	Control     ControlPlane
	OAuth       OAuthClient
	Credentials CredentialStore
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

// A partial environment is rejected instead of falling through to a human login.
func (m *Manager) MachineAccess() (Access, bool, error) {
	endpoint := strings.TrimSpace(m.getenv("SCOPEDB_CLI_ENDPOINT"))
	apiKey := strings.TrimSpace(m.getenv("SCOPEDB_CLI_API_KEY"))
	if endpoint == "" && apiKey == "" {
		return Access{}, false, nil
	}
	if endpoint == "" || apiKey == "" {
		return Access{}, false, fmt.Errorf("%w: SCOPEDB_CLI_ENDPOINT and SCOPEDB_CLI_API_KEY must be set together", ErrInvalidMachineEnv)
	}
	return Access{Endpoint: endpoint, APIKey: apiKey, Mode: "api_key"}, true, nil
}

// RenewableLogin reports the stored login that can still be renewed, without refreshing it.
func (m *Manager) RenewableLogin() (credential.State, bool, error) {
	state, err := m.load()
	var keyringErr *credential.KeyringError
	switch {
	case errors.Is(err, ErrNotLoggedIn):
		return credential.State{}, false, nil
	case errors.As(err, &keyringErr):
		// New logins can fall back to a file when the keyring is unavailable.
		return credential.State{}, false, nil
	case err != nil:
		return credential.State{}, false, err
	}
	// An expired refresh token cannot renew the login, so the record can no longer work and a new login may replace it.
	if !state.RefreshTokenExpiresAt.IsZero() && !state.RefreshTokenExpiresAt.After(m.now()) {
		return credential.State{}, false, nil
	}
	return state, true, nil
}

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

// The selection survives a login, because signing in again does not change which workspace the profile uses.
// The lock serializes login with refresh and prevents replacing a concurrent login.
func (m *Manager) SaveLogin(ctx context.Context, tokens controlplane.TokenSet) (credential.State, bool, string, error) {
	lock, err := filelock.Acquire(ctx, m.LockFile)
	if err != nil {
		return credential.State{}, false, "", err
	}
	defer func() { _ = lock.Close() }()

	previous, err := m.Credentials.Load(m.ControlURL)
	previousFound := err == nil
	var keyringErr *credential.KeyringError
	switch {
	case errors.Is(err, credential.ErrNotFound), errors.Is(err, credential.ErrInvalidState), errors.As(err, &keyringErr):
		previous = credential.State{}
	case err != nil:
		return credential.State{}, false, "", fmt.Errorf("%w: %w", ErrCredentialsUnreadable, err)
	}
	if previousFound && (previous.RefreshTokenExpiresAt.IsZero() || previous.RefreshTokenExpiresAt.After(m.now())) {
		return credential.State{}, false, "", ErrAlreadyLoggedIn
	}
	state, err := m.tokenState(credential.State{}, tokens)
	if err != nil {
		return credential.State{}, false, "", err
	}
	state.WorkspaceID = previous.WorkspaceID
	if err := m.Credentials.Replace(m.ControlURL, state); err != nil {
		return credential.State{}, false, "", err
	}
	return previous, previousFound, state.AccessToken, nil
}

// RestoreLogin puts back the login SaveLogin replaced, under the same lock, when the surrounding
// configuration write fails. It only acts while the record still holds the login SaveLogin wrote, so
// a concurrent logout or newer login is never overwritten or deleted.
func (m *Manager) RestoreLogin(ctx context.Context, state credential.State, found bool, writtenAccessToken string) error {
	lock, err := filelock.Acquire(ctx, m.LockFile)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()

	current, err := m.Credentials.Load(m.ControlURL)
	switch {
	case errors.Is(err, credential.ErrNotFound), errors.Is(err, credential.ErrInvalidState):
		return nil
	case err != nil:
		return err
	}
	if current.AccessToken != writtenAccessToken {
		return nil
	}
	if found {
		return m.Credentials.Replace(m.ControlURL, state)
	}
	return m.deleteIgnoringMissing()
}

type WorkspaceAccess struct {
	AccessToken string
	WorkspaceID string
}

// LoadWorkspaceAccess resolves the account credential and workspace together for control-plane commands.
func (m *Manager) LoadWorkspaceAccess(ctx context.Context) (WorkspaceAccess, error) {
	account, state, err := m.Account(ctx)
	if err != nil {
		return WorkspaceAccess{}, err
	}
	if err := RequireWorkspace(account); err != nil {
		return WorkspaceAccess{}, err
	}
	return WorkspaceAccess{AccessToken: state.AccessToken, WorkspaceID: account.SelectedWorkspaceID}, nil
}

// Account returns account details and the credential used to read them as one snapshot.
func (m *Manager) Account(ctx context.Context) (Account, credential.State, error) {
	state, err := m.LoadAccess(ctx)
	if err != nil {
		return Account{}, credential.State{}, err
	}
	for attempt := 0; ; attempt++ {
		account, err := m.readAccount(ctx, state)
		if err == nil {
			return account, state, nil
		}
		if attempt > 0 || !isControlUnauthorized(err) {
			return Account{}, credential.State{}, err
		}
		// A valid access token can still be rejected after its grant is revoked. Refresh to tell
		// that apart from a transient 401; invalid_grant removes the dead login in refresh.
		state, err = m.refresh(ctx, state)
		if err != nil {
			return Account{}, credential.State{}, err
		}
	}
}

func (m *Manager) readAccount(ctx context.Context, state credential.State) (Account, error) {
	user, err := m.Control.GetUser(ctx, state.AccessToken)
	if err != nil {
		return Account{}, err
	}
	workspaces, err := m.Control.ListWorkspaces(ctx, state.AccessToken)
	if err != nil {
		return Account{}, err
	}
	return Account{User: user, Workspaces: workspaces, SelectedWorkspaceID: state.WorkspaceID}, nil
}

func isControlUnauthorized(err error) bool {
	var controlErr *controlplane.Error
	return errors.As(err, &controlErr) && controlErr.Status == http.StatusUnauthorized
}

// SelectWorkspace updates the local selection; an empty ID clears it. The
// record is re-read under the lock so a concurrent refresh or data-token cache write is preserved.
func (m *Manager) SelectWorkspace(ctx context.Context, workspaceID string) error {
	lock, err := filelock.Acquire(ctx, m.LockFile)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()

	state, err := m.load()
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
		return fmt.Errorf("save workspace selection: %w", err)
	}
	return nil
}

// The login stays usable until it expires or the user revokes it in the Console.
type LogoutCleanupError struct{ Err error }

func (e *LogoutCleanupError) Error() string {
	return fmt.Sprintf("local credentials removed, but the login could not be revoked: %s", e.Err)
}

func (e *LogoutCleanupError) Unwrap() error { return e.Err }

// Local credentials are removed even when revocation fails, and the failure is reported so the user
// knows the login may still exist.
func (m *Manager) Logout(ctx context.Context) error {
	lock, err := filelock.Acquire(ctx, m.LockFile)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()

	state, err := m.Credentials.Load(m.ControlURL)
	if errors.Is(err, credential.ErrInvalidState) {
		return m.deleteIgnoringMissing()
	}
	if errors.Is(err, credential.ErrNotFound) {
		// A prior logout may have cleared the file while the keyring was
		// unavailable. Retry cleanup without reviving that old login.
		if err := m.deleteIgnoringMissing(); err != nil {
			return err
		}
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

func (m *Manager) ResolveDataAccess(ctx context.Context) (Access, error) {
	if access, active, err := m.MachineAccess(); active || err != nil {
		return access, err
	}

	account, state, err := m.Account(ctx)
	if err != nil {
		return Access{}, err
	}
	if err := RequireWorkspace(account); err != nil {
		return Access{}, err
	}
	// Refresh may load a newer workspace selection; this command keeps its resolved target.
	workspaceID := account.SelectedWorkspaceID
	details, err := m.Control.GetWorkspace(ctx, state.AccessToken, workspaceID)
	if err != nil {
		return Access{}, err
	}
	if details.Provisioning.Status != "ready" {
		return Access{}, fmt.Errorf("workspace %s is %s", workspaceID, details.Provisioning.Status)
	}
	if details.Connection.APIBaseURL == "" {
		return Access{}, fmt.Errorf("workspace %s has no data-plane endpoint", workspaceID)
	}

	if state.DataToken != "" && state.DataTokenWorkspaceID == workspaceID && state.DataTokenExpiresAt.After(m.now().Add(30*time.Second)) {
		return Access{
			Endpoint:    details.Connection.APIBaseURL,
			APIKey:      state.DataToken,
			WorkspaceID: workspaceID,
			Mode:        "oauth",
		}, nil
	}

	exchanged, err := m.Control.ExchangeToken(ctx, state.AccessToken, workspaceID)
	if isControlUnauthorized(err) {
		state, err = m.refresh(ctx, state)
		if err != nil {
			return Access{}, err
		}
		exchanged, err = m.Control.ExchangeToken(ctx, state.AccessToken, workspaceID)
	}
	if err != nil {
		return Access{}, err
	}
	if !strings.EqualFold(exchanged.TokenType, "Bearer") || exchanged.AccessToken == "" || exchanged.ExpiresAt.IsZero() {
		return Access{}, fmt.Errorf("token exchange returned an invalid credential")
	}
	if err := m.saveDataToken(ctx, state.AccessToken, workspaceID, exchanged); err != nil {
		return Access{}, err
	}
	return Access{
		Endpoint:    details.Connection.APIBaseURL,
		APIKey:      exchanged.AccessToken,
		WorkspaceID: workspaceID,
		Mode:        "oauth",
	}, nil
}

// saveDataToken merges the exchange credential into the current record instead of writing back the
// state loaded before the exchange, which would revert a concurrent rotation or workspace selection.
func (m *Manager) saveDataToken(ctx context.Context, accessToken, workspaceID string, exchanged controlplane.TokenExchangeResponse) error {
	lock, err := filelock.Acquire(ctx, m.LockFile)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()

	state, err := m.load()
	if errors.Is(err, ErrNotLoggedIn) {
		return nil
	}
	if err != nil {
		return err
	}
	if state.AccessToken != accessToken {
		return nil
	}
	state.DataToken = exchanged.AccessToken
	state.DataTokenWorkspaceID = workspaceID
	state.DataTokenExpiresAt = exchanged.ExpiresAt.UTC()
	if err := m.Credentials.Save(m.ControlURL, state); err != nil {
		return fmt.Errorf("save short-lived data credential: %w", err)
	}
	return nil
}

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
	for _, workspace := range account.Workspaces {
		if workspace.ID != account.SelectedWorkspaceID {
			continue
		}
		if workspace.ScheduledForDeletion() {
			return ErrWorkspaceUnavailable
		}
		return nil
	}
	return ErrWorkspaceUnavailable
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
			// The reuse-detection and idle-expiry rules end the whole grant, so the stored credentials can never work again.
			_ = m.Credentials.Delete(m.ControlURL)
			return credential.State{}, fmt.Errorf("%w: %s", ErrLoginExpired, refreshErr)
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

// A transport failure or an HTTP 5xx may mean the response was lost; a 429 must not be retried.
func retryableRefresh(err error) bool {
	var protocol *controlplane.OAuthError
	if !errors.As(err, &protocol) {
		return false
	}
	if protocol.Status == 0 {
		return true
	}
	return protocol.Status >= 500 || (protocol.Status >= 200 && protocol.Status < 300 && protocol.Retryable)
}
