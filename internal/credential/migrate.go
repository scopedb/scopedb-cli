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
	"crypto/rand"
	"errors"
	"fmt"
)

// MigrateLegacy moves one origin's old login to a single profile, retaining its backend.
// Callers hold both the config-directory lock and the cross-directory migration lock.
// The source claim is durable before copying; retries use an existing target rather
// than replaying a stale refresh token after an interrupted migration.
func MigrateLegacy(origin, reference string, legacy, target *Stores) (State, bool, error) {
	source := legacy.Plaintext
	state, err := source.Load(origin)
	if errors.Is(err, ErrNotFound) {
		source = legacy.Keyring
		state, err = source.Load(origin)
		state.Source = SourceKeyring
	} else {
		state.Source = SourcePlaintext
	}
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidState) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	if state.MigratedTo != "" && state.MigratedTo != reference || state.Cleared && state.MigratedTo == "" {
		return State{}, false, nil
	}
	if state.Source == SourcePlaintext {
		shared, err := legacy.Keyring.Load(origin)
		if err == nil && shared.MigratedTo != "" && shared.MigratedTo != reference {
			return State{}, false, nil
		}
		if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrInvalidState) {
			return State{}, false, err
		}
	}
	if state.MigratedTo == "" {
		state.MigratedTo = reference
		if state.LoginID == "" {
			state.LoginID = rand.Text()
		}
		if err := source.Save(origin, state); err != nil {
			return State{}, false, fmt.Errorf("claim legacy login: %w", err)
		}
	}

	// A stale legacy keyring entry must not become another directory's login.
	// Keep the source claim on failure so a retry can finish without copying twice.
	if state.Source == SourcePlaintext {
		if err := legacy.Keyring.Save(origin, State{Cleared: true, MigratedTo: reference}); err != nil {
			return State{}, false, fmt.Errorf("clear legacy keyring credentials before migration: %w", err)
		}
	}
	destination := target.Keyring
	if state.Source == SourcePlaintext {
		destination = target.Plaintext
	}
	migrated, err := destination.Load(origin)
	if errors.Is(err, ErrNotFound) {
		if state.Cleared {
			return State{}, false, nil
		}
		migrated = state
		migrated.MigratedTo = ""
		if err := destination.Save(origin, migrated); err != nil {
			return State{}, false, fmt.Errorf("move legacy login: %w", err)
		}
	} else if err != nil {
		return State{}, false, err
	}
	if err := source.Save(origin, State{Cleared: true, MigratedTo: reference}); err != nil {
		return State{}, false, fmt.Errorf("clear migrated login: %w", err)
	}
	migrated.Source = state.Source
	return migrated, !migrated.Cleared, nil
}
