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
	"encoding/json"
	"errors"
	"fmt"

	keyring "github.com/zalando/go-keyring"
)

const keyringService = "io.scopedb.scope"

// KeyringStore persists credentials in the operating system's secret store.
type KeyringStore struct{}

func NewKeyringStore() *KeyringStore { return &KeyringStore{} }

func (s *KeyringStore) Load(controlURL string) (State, error) {
	encoded, err := keyring.Get(keyringService, profileKey(controlURL))
	if errors.Is(err, keyring.ErrNotFound) {
		return State{}, ErrNotFound
	}
	if err != nil {
		return State{}, fmt.Errorf("read credentials from OS keyring: %w", err)
	}
	var state State
	if err := json.Unmarshal([]byte(encoded), &state); err != nil {
		return State{}, fmt.Errorf("decode credentials from OS keyring: %w", err)
	}
	if err := validate(controlURL, state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (s *KeyringStore) Save(controlURL string, state State) error {
	state = prepare(controlURL, state)
	encoded, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	if err := keyring.Set(keyringService, profileKey(controlURL), string(encoded)); err != nil {
		return fmt.Errorf("write credentials to OS keyring: %w", err)
	}
	return nil
}

func (s *KeyringStore) Delete(controlURL string) error {
	err := keyring.Delete(keyringService, profileKey(controlURL))
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("delete credentials from OS keyring: %w", err)
	}
	return nil
}
