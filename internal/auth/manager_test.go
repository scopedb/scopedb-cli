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
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memoryStore struct {
	state   credential.State
	present bool
	saves   int
}

func (s *memoryStore) Load(string) (credential.State, error) {
	if !s.present {
		return credential.State{}, credential.ErrNotFound
	}
	return s.state, nil
}

func (s *memoryStore) Save(_ string, state credential.State) error {
	s.state = state
	s.present = true
	s.saves++
	return nil
}

func (s *memoryStore) Delete(string) error {
	if !s.present {
		return credential.ErrNotFound
	}
	s.present = false
	return nil
}

type fakeControl struct {
	session       controlplane.Session
	details       controlplane.WorkspaceDetails
	exchange      controlplane.TokenExchangeResponse
	selected      controlplane.LoginResponse
	exchangeCalls int
	selectCalls   int
}

func (f *fakeControl) GetSession(context.Context, string) (controlplane.Session, error) {
	return f.session, nil
}

func (f *fakeControl) GetWorkspace(context.Context, string, string) (controlplane.WorkspaceDetails, error) {
	return f.details, nil
}

func (f *fakeControl) ExchangeToken(context.Context, string, string) (controlplane.TokenExchangeResponse, error) {
	f.exchangeCalls++
	return f.exchange, nil
}

func (f *fakeControl) SelectWorkspace(context.Context, string, string) (controlplane.LoginResponse, error) {
	f.selectCalls++
	return f.selected, nil
}

func TestMachineAccessRequiresCompletePair(t *testing.T) {
	values := map[string]string{"SCOPEDB_ENDPOINT": "https://data.example.com"}
	manager := Manager{Getenv: func(key string) string { return values[key] }}
	_, active, err := manager.MachineAccess()
	assert.False(t, active)
	require.ErrorIs(t, err, ErrInvalidMachineEnv)

	values["SCOPEDB_API_KEY"] = "secret"
	access, active, err := manager.MachineAccess()
	require.NoError(t, err)
	assert.True(t, active)
	assert.Equal(t, Access{Endpoint: "https://data.example.com", APIKey: "secret", Mode: "api_key"}, access)
}

func TestResolveDataAccessUsesCachedToken(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: credential.State{
		SessionToken:         "session",
		WorkspaceID:          "ws-1",
		DataToken:            "cached-data-token",
		DataTokenWorkspaceID: "ws-1",
		DataTokenExpiresAt:   now.Add(time.Hour),
	}}
	control := &fakeControl{
		session: controlplane.Session{CurrentWorkspaceID: "ws-1"},
		details: controlplane.WorkspaceDetails{
			Workspace:    controlplane.Workspace{ID: "ws-1"},
			Connection:   controlplane.Connection{APIBaseURL: "https://data.example.com"},
			Provisioning: controlplane.Provisioning{Status: "ready"},
		},
	}
	manager := Manager{
		ControlURL:  "https://control.example.com",
		Control:     control,
		Credentials: store,
		Now:         func() time.Time { return now },
		Getenv:      func(string) string { return "" },
	}
	access, err := manager.ResolveDataAccess(t.Context())
	require.NoError(t, err)
	assert.Equal(t, Access{
		Endpoint:    "https://data.example.com",
		APIKey:      "cached-data-token",
		WorkspaceID: "ws-1",
		Mode:        "session",
	}, access)
	assert.Zero(t, control.exchangeCalls)
}

func TestResolveDataAccessExchangesExpiringToken(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store := &memoryStore{present: true, state: credential.State{
		SessionToken:         "session",
		WorkspaceID:          "ws-1",
		DataToken:            "almost-expired",
		DataTokenWorkspaceID: "ws-1",
		DataTokenExpiresAt:   now.Add(10 * time.Second),
	}}
	control := &fakeControl{
		session: controlplane.Session{CurrentWorkspaceID: "ws-1"},
		details: controlplane.WorkspaceDetails{
			Connection:   controlplane.Connection{APIBaseURL: "https://data.example.com"},
			Provisioning: controlplane.Provisioning{Status: "ready"},
		},
		exchange: controlplane.TokenExchangeResponse{
			AccessToken: "fresh-data-token",
			TokenType:   "Bearer",
			ExpiresAt:   now.Add(time.Hour),
		},
	}
	manager := Manager{
		ControlURL:  "https://control.example.com",
		Control:     control,
		Credentials: store,
		Now:         func() time.Time { return now },
		Getenv:      func(string) string { return "" },
	}
	access, err := manager.ResolveDataAccess(t.Context())
	require.NoError(t, err)
	assert.Equal(t, Access{
		Endpoint:    "https://data.example.com",
		APIKey:      "fresh-data-token",
		WorkspaceID: "ws-1",
		Mode:        "session",
	}, access)
	assert.Equal(t, credential.State{
		SessionToken:         "session",
		WorkspaceID:          "ws-1",
		DataToken:            "fresh-data-token",
		DataTokenWorkspaceID: "ws-1",
		DataTokenExpiresAt:   now.Add(time.Hour),
	}, store.state)
	assert.Equal(t, 1, control.exchangeCalls)
	assert.Equal(t, 1, store.saves)
}

func TestSelectWorkspaceClearsDataCredential(t *testing.T) {
	store := &memoryStore{present: true}
	control := &fakeControl{selected: controlplane.LoginResponse{Token: "rotated", WorkspaceID: "ws-2"}}
	manager := Manager{ControlURL: "https://control.example.com", Control: control, Credentials: store}
	state := credential.State{
		SessionToken:         "old",
		WorkspaceID:          "ws-1",
		DataToken:            "data",
		DataTokenWorkspaceID: "ws-1",
		DataTokenExpiresAt:   time.Now().Add(time.Hour),
	}
	require.NoError(t, manager.SelectWorkspace(t.Context(), state, "ws-2"))
	assert.Equal(t, credential.State{SessionToken: "rotated", WorkspaceID: "ws-2"}, store.state)
}

func TestLoadSessionWithoutCredentials(t *testing.T) {
	manager := Manager{ControlURL: "https://control.example.com", Credentials: &memoryStore{}}
	_, _, err := manager.LoadSession(t.Context())
	assert.ErrorIs(t, err, ErrNotLoggedIn)
}
