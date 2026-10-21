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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/require"
)

type memoryStore struct {
	mu        sync.Mutex
	state     credential.State
	present   bool
	saves     int
	invalidHi bool
	loadErr   error
	saveErr   error
}

func (s *memoryStore) Load(string) (credential.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return credential.State{}, s.loadErr
	}
	if s.invalidHi {
		return credential.State{}, fmt.Errorf("%w: unsupported version 1; log in again", credential.ErrInvalidState)
	}
	if !s.present {
		return credential.State{}, credential.ErrNotFound
	}
	return s.state, nil
}

func (s *memoryStore) Save(_ string, state credential.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	s.state = state
	s.present = true
	s.saves++
	return nil
}

func (s *memoryStore) Delete(string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.present {
		return credential.ErrNotFound
	}
	s.present = false
	return nil
}

func (s *memoryStore) saved() credential.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *memoryStore) stored() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.present
}

type fakeControl struct {
	user           controlplane.User
	workspaces     []controlplane.Workspace
	details        controlplane.WorkspaceDetails
	exchange       controlplane.TokenExchangeResponse
	onExchange     func()
	getUser        func(string) (controlplane.User, error)
	listWorkspaces func(string) ([]controlplane.Workspace, error)
	exchangeCalls  int
}

func (f *fakeControl) GetUser(_ context.Context, token string) (controlplane.User, error) {
	if f.getUser != nil {
		return f.getUser(token)
	}
	return f.user, nil
}

func (f *fakeControl) ListWorkspaces(_ context.Context, token string) ([]controlplane.Workspace, error) {
	if f.listWorkspaces != nil {
		return f.listWorkspaces(token)
	}
	return f.workspaces, nil
}

func (f *fakeControl) GetWorkspace(context.Context, string, string) (controlplane.WorkspaceDetails, error) {
	return f.details, nil
}

func (f *fakeControl) ExchangeToken(context.Context, string, string) (controlplane.TokenExchangeResponse, error) {
	if f.onExchange != nil {
		f.onExchange()
	}
	f.exchangeCalls++
	return f.exchange, nil
}

type fakeOAuth struct {
	mu        sync.Mutex
	results   []tokenOutcome
	calls     int
	revoked   []string
	onRefresh func()
	rejectAll bool
}

type tokenOutcome struct {
	tokens controlplane.TokenSet
	err    error
}

func (f *fakeOAuth) RefreshToken(context.Context, string) (controlplane.TokenSet, error) {
	if f.onRefresh != nil {
		f.onRefresh()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.rejectAll {
		return controlplane.TokenSet{}, &controlplane.OAuthError{Code: "invalid_grant", Status: http.StatusBadRequest}
	}
	if len(f.results) == 0 {
		return controlplane.TokenSet{}, errors.New("unexpected refresh")
	}
	outcome := f.results[0]
	if len(f.results) > 1 {
		f.results = f.results[1:]
	}
	return outcome.tokens, outcome.err
}

func (f *fakeOAuth) RevokeToken(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, token)
	return nil
}

func (f *fakeOAuth) refreshCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func accessTokens(access, refresh string) controlplane.TokenSet {
	return controlplane.TokenSet{
		AccessToken: access, TokenType: "Bearer", ExpiresIn: 3600,
		RefreshToken: refresh, RefreshTokenExpiresIn: 1209600,
	}
}

func loginState(now time.Time, accessExpiry time.Time) credential.State {
	return credential.State{
		AccessToken:           "oat_old",
		AccessTokenExpiresAt:  accessExpiry,
		RefreshToken:          "ort_old",
		RefreshTokenExpiresAt: now.Add(24 * time.Hour),
		WorkspaceID:           "ws-1",
	}
}

func newManager(t *testing.T, store credential.Store, control ControlPlane, oauth OAuthClient, now time.Time) *Manager {
	return &Manager{
		ControlURL:  "https://control.example.com",
		Control:     control,
		OAuth:       oauth,
		Credentials: store,
		LockFile:    filepath.Join(t.TempDir(), "credentials.lock"),
		Now:         func() time.Time { return now },
		Sleep:       func(time.Duration) {},
		Getenv:      func(string) string { return "" },
	}
}

func TestMachineAccessRequiresCompletePair(t *testing.T) {
	values := map[string]string{"SCOPEDB_ENDPOINT": "https://data.example.com"}
	manager := Manager{Getenv: func(key string) string { return values[key] }}
	_, active, err := manager.MachineAccess()
	require.False(t, active)
	require.ErrorIs(t, err, ErrInvalidMachineEnv)

	values["SCOPEDB_API_KEY"] = "secret"
	access, active, err := manager.MachineAccess()
	require.NoError(t, err)
	require.True(t, active)
	require.Equal(t, Access{Endpoint: "https://data.example.com", APIKey: "secret", Mode: "api_key"}, access)
}

func TestLoadAccessReturnsFreshTokenWithoutRefresh(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Hour))}
	oauth := &fakeOAuth{}
	manager := newManager(t, store, &fakeControl{}, oauth, now)

	state, err := manager.LoadAccess(t.Context())
	require.NoError(t, err)
	require.Equal(t, "oat_old", state.AccessToken)
	require.Zero(t, oauth.refreshCalls())
}

func TestAccountClearsARevokedGrant(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Hour))}
	control := &fakeControl{getUser: func(token string) (controlplane.User, error) {
		if token == "oat_old" {
			return controlplane.User{}, &controlplane.Error{Status: http.StatusUnauthorized, Message: "invalid access token"}
		}
		return controlplane.User{Email: "dev@example.com", Status: "active"}, nil
	}}
	manager := newManager(t, store, control, &fakeOAuth{rejectAll: true}, now)

	_, err := manager.Account(t.Context())
	require.ErrorIs(t, err, ErrLoginExpired)
	require.False(t, store.stored())
}

func TestAccountRetriesAfterRefreshingARejectedAccessToken(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Hour))}
	control := &fakeControl{getUser: func(token string) (controlplane.User, error) {
		if token == "oat_old" {
			return controlplane.User{}, &controlplane.Error{Status: http.StatusUnauthorized, Message: "invalid access token"}
		}
		return controlplane.User{Email: "dev@example.com", Status: "active"}, nil
	}}
	oauth := &fakeOAuth{results: []tokenOutcome{{tokens: accessTokens("oat_new", "ort_new")}}}
	manager := newManager(t, store, control, oauth, now)

	account, err := manager.Account(t.Context())
	require.NoError(t, err)
	require.Equal(t, "dev@example.com", account.User.Email)
	require.Equal(t, 1, oauth.refreshCalls())
	require.Equal(t, "oat_new", store.saved().AccessToken)
	require.True(t, store.stored())
}

func TestAccountKeepsACredentialRejectedWithForbidden(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Hour))}
	control := &fakeControl{getUser: func(string) (controlplane.User, error) {
		return controlplane.User{}, &controlplane.Error{Status: http.StatusForbidden, Message: "forbidden"}
	}}
	oauth := &fakeOAuth{}
	manager := newManager(t, store, control, oauth, now)

	_, err := manager.Account(t.Context())
	require.Error(t, err)
	require.Zero(t, oauth.refreshCalls())
	require.True(t, store.stored())
}

func TestLoadAccessRefreshesExpiringToken(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(30*time.Second))}
	oauth := &fakeOAuth{results: []tokenOutcome{{tokens: accessTokens("oat_new", "ort_new")}}}
	manager := newManager(t, store, &fakeControl{}, oauth, now)
	manager.LockFile = filepath.Join(t.TempDir(), "credentials.lock")

	state, err := manager.LoadAccess(t.Context())
	require.NoError(t, err)
	require.Equal(t, "oat_new", state.AccessToken)
	require.Equal(t, "ort_new", state.RefreshToken)
	require.Equal(t, now.Add(time.Hour), state.AccessTokenExpiresAt)
	require.Equal(t, now.Add(14*24*time.Hour), state.RefreshTokenExpiresAt)
	require.Equal(t, state, store.saved())
	require.Equal(t, 1, oauth.refreshCalls())
}

func TestLoadAccessRetriesServerFailures(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Second))}
	oauth := &fakeOAuth{results: []tokenOutcome{
		{err: &controlplane.OAuthError{Code: "server_error", Status: http.StatusServiceUnavailable}},
		{err: &controlplane.OAuthError{Err: errors.New("connection reset")}},
		{tokens: accessTokens("oat_new", "ort_new")},
	}}
	manager := newManager(t, store, &fakeControl{}, oauth, now)
	manager.LockFile = filepath.Join(t.TempDir(), "credentials.lock")

	state, err := manager.LoadAccess(t.Context())
	require.NoError(t, err)
	require.Equal(t, "oat_new", state.AccessToken)
	require.Equal(t, 3, oauth.refreshCalls())
}

func TestLoadAccessDoesNotRetryRateLimits(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Second))}
	rateLimited := &controlplane.OAuthError{Code: "slow_down", Status: http.StatusTooManyRequests}
	oauth := &fakeOAuth{results: []tokenOutcome{{err: rateLimited}}}
	manager := newManager(t, store, &fakeControl{}, oauth, now)
	manager.LockFile = filepath.Join(t.TempDir(), "credentials.lock")

	_, err := manager.LoadAccess(t.Context())
	require.ErrorIs(t, err, rateLimited)
	require.Equal(t, 1, oauth.refreshCalls())
	require.True(t, store.stored(), "a rate limit must keep the stored credentials")
}

func TestLoadAccessDeletesCredentialsWhenRefreshIsRejected(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Second))}
	manager := newManager(t, store, &fakeControl{}, &fakeOAuth{rejectAll: true}, now)
	manager.LockFile = filepath.Join(t.TempDir(), "credentials.lock")

	_, err := manager.LoadAccess(t.Context())
	require.ErrorIs(t, err, ErrLoginExpired)
	require.False(t, store.stored())
}

func TestLoadAccessAdoptsAnotherProcessRotation(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Second))}
	oauth := &fakeOAuth{}
	manager := newManager(t, store, &fakeControl{}, oauth, now)
	manager.LockFile = filepath.Join(t.TempDir(), "credentials.lock")

	rotated := store.saved()
	rotated.AccessToken = "oat_rotated"
	rotated.AccessTokenExpiresAt = now.Add(time.Hour)
	rotated.RefreshToken = "ort_rotated"
	require.NoError(t, store.Save(manager.ControlURL, rotated))

	state, err := manager.LoadAccess(t.Context())
	require.NoError(t, err)
	require.Equal(t, "oat_rotated", state.AccessToken)
	require.Zero(t, oauth.refreshCalls())
}

func TestConcurrentRefreshRotatesOnce(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Second))}
	oauth := &fakeOAuth{results: []tokenOutcome{{tokens: accessTokens("oat_new", "ort_new")}}}
	lockFile := filepath.Join(t.TempDir(), "credentials.lock")

	first := newManager(t, store, &fakeControl{}, oauth, now)
	first.LockFile = lockFile
	second := newManager(t, store, &fakeControl{}, oauth, now)
	second.LockFile = lockFile

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	oauth.onRefresh = func() {
		once.Do(func() { close(entered) })
		<-release
	}

	results := make(chan error, 2)
	go func() {
		_, err := first.LoadAccess(context.Background())
		results <- err
	}()
	<-entered
	go func() {
		_, err := second.LoadAccess(context.Background())
		results <- err
	}()
	close(release)
	require.NoError(t, <-results)
	require.NoError(t, <-results)
	require.Equal(t, 1, oauth.refreshCalls())
	require.Equal(t, 1, store.saves)
}

func TestLoadAccessWithoutCredentials(t *testing.T) {
	manager := Manager{ControlURL: "https://control.example.com", Credentials: &memoryStore{}}
	_, err := manager.LoadAccess(t.Context())
	require.ErrorIs(t, err, ErrNotLoggedIn)
}

func TestLoadAccessRejectsUnusableStoredState(t *testing.T) {
	manager := Manager{ControlURL: "https://control.example.com", Credentials: &memoryStore{invalidHi: true}}
	_, err := manager.LoadAccess(t.Context())
	require.ErrorIs(t, err, ErrNotLoggedIn)
}

func TestRequireWorkspace(t *testing.T) {
	for _, tc := range []struct {
		name    string
		account Account
		want    error
	}{
		{"pending account", Account{User: controlplane.User{Status: "pending"}}, ErrApprovalRequired},
		{"no workspaces", Account{User: controlplane.User{Status: "active"}}, ErrNoWorkspaces},
		{"no selection", Account{User: controlplane.User{Status: "active"}, Workspaces: []controlplane.Workspace{{ID: "ws-1"}}}, ErrNoWorkspaceSelected},
		{"selected", Account{User: controlplane.User{Status: "active"}, Workspaces: []controlplane.Workspace{{ID: "ws-1"}}, SelectedWorkspaceID: "ws-1"}, nil},
		{"selection not owned", Account{User: controlplane.User{Status: "active"}, Workspaces: []controlplane.Workspace{{ID: "ws-2"}}, SelectedWorkspaceID: "ws-1"}, ErrWorkspaceUnavailable},
		{"selection scheduled", Account{User: controlplane.User{Status: "active"}, Workspaces: []controlplane.Workspace{{ID: "ws-1", ScheduledForDeletionAt: func() *time.Time { now := time.Now().Add(time.Hour); return &now }()}}, SelectedWorkspaceID: "ws-1"}, ErrWorkspaceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, RequireWorkspace(tc.account), tc.want)
		})
	}
}

func TestSelectWorkspaceClearsDataCredential(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	state := loginState(now, now.Add(time.Hour))
	state.DataToken = "data"
	state.DataTokenWorkspaceID = "ws-1"
	state.DataTokenExpiresAt = now.Add(time.Hour)
	store := &memoryStore{present: true, state: state}
	manager := newManager(t, store, &fakeControl{}, &fakeOAuth{}, now)

	require.NoError(t, manager.SelectWorkspace(t.Context(), "ws-2"))
	require.Equal(t, "ws-2", store.saved().WorkspaceID)
	require.Empty(t, store.saved().DataToken)
}

func TestSelectWorkspaceSerializesWithRefresh(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Second))}
	oauth := &fakeOAuth{results: []tokenOutcome{{tokens: accessTokens("oat_new", "ort_new")}}}
	manager := newManager(t, store, &fakeControl{}, oauth, now)

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	oauth.onRefresh = func() {
		once.Do(func() { close(entered) })
		<-release
	}

	refreshDone := make(chan error, 1)
	go func() {
		_, err := manager.LoadAccess(context.Background())
		refreshDone <- err
	}()
	<-entered

	selectDone := make(chan error, 1)
	go func() {
		selectDone <- manager.SelectWorkspace(context.Background(), "ws-2")
	}()
	close(release)
	require.NoError(t, <-refreshDone)
	require.NoError(t, <-selectDone)
	require.Equal(t, "oat_new", store.saved().AccessToken)
	require.Equal(t, "ort_new", store.saved().RefreshToken)
	require.Equal(t, "ws-2", store.saved().WorkspaceID)
}

func TestSaveDataTokenPreservesConcurrentSelection(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Hour))}
	entered := make(chan struct{})
	release := make(chan struct{})
	control := &fakeControl{
		user:       controlplane.User{Status: "active"},
		workspaces: []controlplane.Workspace{{ID: "ws-1"}},
		details: controlplane.WorkspaceDetails{
			Workspace:    controlplane.Workspace{ID: "ws-1"},
			Connection:   controlplane.Connection{APIBaseURL: "https://data.example.com"},
			Provisioning: controlplane.Provisioning{Status: "ready"},
		},
		exchange: controlplane.TokenExchangeResponse{
			AccessToken: "data-token",
			TokenType:   "Bearer",
			ExpiresAt:   now.Add(time.Hour),
		},
		onExchange: func() {
			close(entered)
			<-release
		},
	}
	manager := newManager(t, store, control, &fakeOAuth{}, now)

	done := make(chan error, 1)
	go func() {
		_, err := manager.ResolveDataAccess(context.Background())
		done <- err
	}()
	<-entered
	require.NoError(t, manager.SelectWorkspace(context.Background(), "ws-2"))
	close(release)
	require.NoError(t, <-done)
	require.Equal(t, "ws-2", store.saved().WorkspaceID)
	require.Equal(t, "data-token", store.saved().DataToken)
	require.Equal(t, "ws-1", store.saved().DataTokenWorkspaceID)
}

func TestResolveDataAccessUsesCachedToken(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	state := loginState(now, now.Add(time.Hour))
	state.DataToken = "cached-data-token"
	state.DataTokenWorkspaceID = "ws-1"
	state.DataTokenExpiresAt = now.Add(time.Hour)
	store := &memoryStore{present: true, state: state}
	control := &fakeControl{
		user:       controlplane.User{Status: "active"},
		workspaces: []controlplane.Workspace{{ID: "ws-1"}},
		details: controlplane.WorkspaceDetails{
			Workspace:    controlplane.Workspace{ID: "ws-1"},
			Connection:   controlplane.Connection{APIBaseURL: "https://data.example.com"},
			Provisioning: controlplane.Provisioning{Status: "ready"},
		},
	}
	manager := newManager(t, store, control, &fakeOAuth{}, now)

	access, err := manager.ResolveDataAccess(t.Context())
	require.NoError(t, err)
	require.Equal(t, Access{
		Endpoint:    "https://data.example.com",
		APIKey:      "cached-data-token",
		WorkspaceID: "ws-1",
		Mode:        "oauth",
	}, access)
	require.Zero(t, control.exchangeCalls)
}

func TestResolveDataAccessExchangesExpiringToken(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	state := loginState(now, now.Add(time.Hour))
	state.DataToken = "almost-expired"
	state.DataTokenWorkspaceID = "ws-1"
	state.DataTokenExpiresAt = now.Add(10 * time.Second)
	store := &memoryStore{present: true, state: state}
	control := &fakeControl{
		user:       controlplane.User{Status: "active"},
		workspaces: []controlplane.Workspace{{ID: "ws-1"}},
		details: controlplane.WorkspaceDetails{
			Connection:   controlplane.Connection{APIBaseURL: "https://data.example.com"},
			Provisioning: controlplane.Provisioning{Status: "ready"},
		},
		exchange: controlplane.TokenExchangeResponse{
			AccessToken: "fresh-data-token", TokenType: "Bearer", ExpiresAt: now.Add(time.Hour),
		},
	}
	manager := newManager(t, store, control, &fakeOAuth{}, now)

	access, err := manager.ResolveDataAccess(t.Context())
	require.NoError(t, err)
	require.Equal(t, "fresh-data-token", access.APIKey)
	require.Equal(t, "fresh-data-token", store.saved().DataToken)
	require.Equal(t, 1, control.exchangeCalls)
}

func TestResolveDataAccessRequiresSelection(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	state := loginState(now, now.Add(time.Hour))
	state.WorkspaceID = ""
	store := &memoryStore{present: true, state: state}
	control := &fakeControl{user: controlplane.User{Status: "active"}, workspaces: []controlplane.Workspace{{ID: "ws-1"}}}
	manager := newManager(t, store, control, &fakeOAuth{}, now)

	_, err := manager.ResolveDataAccess(t.Context())
	require.ErrorIs(t, err, ErrNoWorkspaceSelected)
	require.Zero(t, control.exchangeCalls)
}

func TestLogoutRevokesAndDeletes(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Hour))}
	oauth := &fakeOAuth{}
	manager := newManager(t, store, &fakeControl{}, oauth, now)

	require.NoError(t, manager.Logout(t.Context()))
	require.Equal(t, []string{"ort_old"}, oauth.revoked)
	require.False(t, store.stored())
}

func TestLogoutWithoutCredentials(t *testing.T) {
	manager := newManager(t, &memoryStore{}, &fakeControl{}, &fakeOAuth{}, time.Now())
	require.ErrorIs(t, manager.Logout(t.Context()), ErrNotLoggedIn)
}

func TestLogoutRemovesCredentialsWhenRevocationFails(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Hour))}
	manager := newManager(t, store, &fakeControl{}, revokeFailOAuth{}, now)

	err := manager.Logout(t.Context())
	var cleanup *LogoutCleanupError
	require.ErrorAs(t, err, &cleanup)
	require.False(t, store.stored())
}

type revokeFailOAuth struct{}

func (revokeFailOAuth) RefreshToken(context.Context, string) (controlplane.TokenSet, error) {
	return controlplane.TokenSet{}, errors.New("unexpected refresh")
}

func (revokeFailOAuth) RevokeToken(context.Context, string) error {
	return errors.New("revocation unavailable")
}

func TestSaveLoginRejectsIncompleteTokenResponse(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{}
	manager := newManager(t, store, &fakeControl{}, &fakeOAuth{}, now)

	for _, tokens := range []controlplane.TokenSet{
		{RefreshToken: "ort_new", ExpiresIn: 3600},
		{AccessToken: "oat_new", ExpiresIn: 3600},
		{AccessToken: "oat_new", RefreshToken: "ort_new"},
	} {
		_, _, _, err := manager.SaveLogin(t.Context(), tokens)
		require.Error(t, err)
	}
	require.False(t, store.stored())
}

func TestSaveLoginStoresBothTokens(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{}
	manager := newManager(t, store, &fakeControl{}, &fakeOAuth{}, now)

	_, _, _, err := manager.SaveLogin(t.Context(), accessTokens("oat_new", "ort_new"))
	require.NoError(t, err)
	require.Equal(t, "oat_new", store.saved().AccessToken)
	require.Equal(t, "ort_new", store.saved().RefreshToken)
	require.Equal(t, now.Add(time.Hour), store.saved().AccessTokenExpiresAt)
	require.Empty(t, store.saved().WorkspaceID)
}

func TestSaveLoginKeepsStoredSelectionAndClearsDataToken(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	state := loginState(now, now.Add(time.Hour))
	state.DataToken = "data-token"
	state.DataTokenWorkspaceID = "ws-1"
	state.DataTokenExpiresAt = now.Add(time.Hour)
	store := &memoryStore{present: true, state: state}
	manager := newManager(t, store, &fakeControl{}, &fakeOAuth{}, now)

	_, _, _, err := manager.SaveLogin(t.Context(), accessTokens("oat_new", "ort_new"))
	require.NoError(t, err)
	require.Equal(t, "ws-1", store.saved().WorkspaceID)
	require.Equal(t, "oat_new", store.saved().AccessToken)
	require.Empty(t, store.saved().DataToken)
	require.Empty(t, store.saved().DataTokenWorkspaceID)
	require.True(t, store.saved().DataTokenExpiresAt.IsZero())
}

func TestSaveLoginReplacesUnreadableStoredState(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{invalidHi: true}
	manager := newManager(t, store, &fakeControl{}, &fakeOAuth{}, now)

	_, _, _, err := manager.SaveLogin(t.Context(), accessTokens("oat_new", "ort_new"))
	require.NoError(t, err)
	require.Equal(t, "oat_new", store.saved().AccessToken)
	require.Empty(t, store.saved().WorkspaceID)
}

func TestSaveLoginReportsCredentialLoadFailure(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{loadErr: errors.New("credential store unavailable")}
	manager := newManager(t, store, &fakeControl{}, &fakeOAuth{}, now)

	_, _, _, err := manager.SaveLogin(t.Context(), accessTokens("oat_new", "ort_new"))
	require.ErrorContains(t, err, "credential store unavailable")
	require.False(t, store.stored())
}

func TestRestoreLoginDoesNotReplaceANewerLogin(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{}
	manager := newManager(t, store, &fakeControl{}, &fakeOAuth{}, now)

	previous, found, written, err := manager.SaveLogin(t.Context(), accessTokens("oat_login", "ort_login"))
	require.NoError(t, err)
	require.False(t, found)
	require.Equal(t, "oat_login", written)

	newer := loginState(now, now.Add(time.Hour))
	newer.AccessToken = "oat_newer"
	newer.RefreshToken = "ort_newer"
	require.NoError(t, store.Save(manager.ControlURL, newer))

	require.NoError(t, manager.RestoreLogin(t.Context(), previous, found, written))
	require.Equal(t, "oat_newer", store.saved().AccessToken)
}

func TestClearWorkspaceDropsSelectionAndDataToken(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	state := loginState(now, now.Add(time.Hour))
	state.DataToken = "data-token"
	state.DataTokenWorkspaceID = "ws-1"
	state.DataTokenExpiresAt = now.Add(time.Hour)
	store := &memoryStore{present: true, state: state}
	manager := newManager(t, store, &fakeControl{}, &fakeOAuth{}, now)

	require.NoError(t, manager.ClearWorkspace(t.Context()))
	require.Empty(t, store.saved().WorkspaceID)
	require.Empty(t, store.saved().DataToken)
	require.Empty(t, store.saved().DataTokenWorkspaceID)
	require.True(t, store.saved().DataTokenExpiresAt.IsZero())
	require.Equal(t, "oat_old", store.saved().AccessToken)
	require.Equal(t, 1, store.saves)
}

func TestClearWorkspaceWithoutSelectionKeepsCredentials(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	state := loginState(now, now.Add(time.Hour))
	state.WorkspaceID = ""
	store := &memoryStore{present: true, state: state}
	manager := newManager(t, store, &fakeControl{}, &fakeOAuth{}, now)

	require.NoError(t, manager.ClearWorkspace(t.Context()))
	require.Zero(t, store.saves)
}

func TestClearWorkspaceWithoutLogin(t *testing.T) {
	manager := newManager(t, &memoryStore{}, &fakeControl{}, &fakeOAuth{}, time.Now())
	require.ErrorIs(t, manager.ClearWorkspace(t.Context()), ErrNotLoggedIn)
}

func TestClearWorkspaceReportsSaveFailure(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: loginState(now, now.Add(time.Hour)), saveErr: errors.New("disk full")}
	manager := newManager(t, store, &fakeControl{}, &fakeOAuth{}, now)

	err := manager.ClearWorkspace(t.Context())
	require.ErrorContains(t, err, "workspace selection could not be cleared")
	require.ErrorContains(t, err, "disk full")
}
