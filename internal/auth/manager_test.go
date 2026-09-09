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
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
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
	if active || !errors.Is(err, ErrInvalidMachineEnv) {
		t.Fatalf("MachineAccess() = active %v, err %v", active, err)
	}
	values["SCOPEDB_API_KEY"] = "secret"
	access, active, err := manager.MachineAccess()
	if err != nil || !active {
		t.Fatalf("MachineAccess() = %#v, %v, %v", access, active, err)
	}
	if access.Endpoint != "https://data.example.com" || access.APIKey != "secret" || access.Mode != "api_key" {
		t.Errorf("access = %#v", access)
	}
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
	access, err := manager.ResolveDataAccess(context.Background())
	if err != nil {
		t.Fatalf("ResolveDataAccess() error = %v", err)
	}
	if access.APIKey != "cached-data-token" || access.WorkspaceID != "ws-1" {
		t.Errorf("access = %#v", access)
	}
	if control.exchangeCalls != 0 {
		t.Errorf("exchange calls = %d, want 0", control.exchangeCalls)
	}
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
	access, err := manager.ResolveDataAccess(context.Background())
	if err != nil {
		t.Fatalf("ResolveDataAccess() error = %v", err)
	}
	if access.APIKey != "fresh-data-token" || store.state.DataToken != "fresh-data-token" {
		t.Errorf("access = %#v, state = %#v", access, store.state)
	}
	if control.exchangeCalls != 1 || store.saves != 1 {
		t.Errorf("exchange calls = %d, saves = %d", control.exchangeCalls, store.saves)
	}
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
	if err := manager.SelectWorkspace(context.Background(), state, "ws-2"); err != nil {
		t.Fatalf("SelectWorkspace() error = %v", err)
	}
	if store.state.SessionToken != "rotated" || store.state.WorkspaceID != "ws-2" || store.state.DataToken != "" || !store.state.DataTokenExpiresAt.IsZero() {
		t.Errorf("saved state = %#v", store.state)
	}
}

func TestLoadSessionWithoutCredentials(t *testing.T) {
	manager := Manager{ControlURL: "https://control.example.com", Credentials: &memoryStore{}}
	_, _, err := manager.LoadSession(context.Background())
	if !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("LoadSession() error = %v, want ErrNotLoggedIn", err)
	}
}
