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
	"errors"
	"fmt"
)

// Stores resolves existing credentials independently of the next login's
// destination. Mutations must run under the auth manager's shared file lock.
type Stores struct {
	Keyring         Store
	Plaintext       Store
	InsecureStorage bool
	// OnPlaintext reports a successful new plaintext login. A nil fallback
	// means plaintext was explicitly requested; cleanup is an old keyring
	// entry that could not be removed.
	OnPlaintext func(fallback, cleanup error)
}

func (s *Stores) Load(controlURL string) (State, error) {
	// A fallback file is authoritative even if the previously unavailable
	// keyring recovers with an old entry still in it.
	state, err := s.Plaintext.Load(controlURL)
	if err == nil {
		if state.Cleared || state.MigratedTo != "" {
			return State{}, ErrNotFound
		}
		state.Source = SourcePlaintext
		return state, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return State{}, err
	}
	state, err = s.Keyring.Load(controlURL)
	state.Source = SourceKeyring
	if err == nil && (state.Cleared || state.MigratedTo != "") {
		return State{}, ErrNotFound
	}
	return state, err
}

func (s *Stores) Save(controlURL string, state State) error {
	switch state.Source {
	case SourceKeyring:
		return s.Keyring.Save(controlURL, state)
	case SourcePlaintext:
		return s.Plaintext.Save(controlURL, state)
	default:
		return fmt.Errorf("cannot update credentials without a resolved source")
	}
}

// Replace saves a new login, or restores a previous login to its original
// source, and cleans up the other store. Only new logins may fall back.
func (s *Stores) Replace(controlURL string, state State) error {
	newLogin := state.Source == ""
	plaintext := state.Source == SourcePlaintext || (newLogin && s.InsecureStorage)
	var fallback error
	if !plaintext {
		if err := s.Keyring.Save(controlURL, state); err == nil {
			if err := deleteIfPresent(s.Plaintext, controlURL); err != nil {
				// The old file remains authoritative. Do not leave an unused
				// new login in the keyring if completing the switch failed.
				if newLogin {
					err = errors.Join(err, deleteIfPresent(s.Keyring, controlURL))
				}
				return fmt.Errorf("remove previous plaintext credentials: %w", err)
			}
			return nil
		} else if !newLogin {
			return err
		} else {
			fallback = err
		}
	}
	if err := s.Plaintext.Save(controlURL, state); err != nil {
		return errors.Join(fallback, err)
	}
	cleanup := deleteIfPresent(s.Keyring, controlURL)
	if !newLogin {
		return cleanup
	}
	if s.OnPlaintext != nil {
		s.OnPlaintext(fallback, cleanup)
	}
	return nil
}

func (s *Stores) Delete(controlURL string) error {
	if err := deleteIfPresent(s.Keyring, controlURL); err != nil {
		// Clear all local file tokens while preventing a stale keyring login
		// from reappearing later. Keep the cleanup error visible to callers.
		clearErr := s.Plaintext.Save(controlURL, State{Cleared: true})
		return errors.Join(err, clearErr)
	}
	return deleteIfPresent(s.Plaintext, controlURL)
}

func deleteIfPresent(store Store, controlURL string) error {
	err := store.Delete(controlURL)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
