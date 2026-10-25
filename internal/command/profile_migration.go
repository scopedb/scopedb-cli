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

package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/scopedb/scopedb-cli/internal/filelock"
)

var errLegacyMigration = errors.New("legacy credential migration failed")

func (a *app) migrateProfile(ctx context.Context, r *runtimeContext) error {
	// A new configuration directory must never adopt another directory's legacy keyring login.
	// Legacy plaintext records are already local to this directory.
	_, configErr := os.Stat(r.paths.Config)
	_, fileErr := os.Stat(r.paths.CredentialsFile)
	if errors.Is(configErr, os.ErrNotExist) && errors.Is(fileErr, os.ErrNotExist) {
		return nil
	}
	lock, err := filelock.Acquire(ctx, r.paths.LockFile)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	cfg, err := config.Read(r.paths)
	if err != nil {
		return err
	}
	if profile, ok := cfg.Profiles[r.config.ProfileName]; ok {
		if profile.ControlURL != r.config.ControlURL {
			return usageError("profile service changed while the command was starting")
		}
		r.config.SelectedProfile, r.config.ProfileExists = profile, true
		return nil
	}
	// Legacy keyring entries were shared across configuration directories. Serialize
	// their claim separately so two directories cannot adopt the same rotating token.
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	migrationLock := filepath.Join(os.TempDir(), "scopedb-migration-"+config.CredentialReference(config.Paths{Directory: home}, "legacy")+".lock")
	shared, err := filelock.Acquire(ctx, migrationLock)
	if err != nil {
		return err
	}
	defer func() { _ = shared.Close() }()
	keyring, err := a.credentialFactory(credential.SourceKeyring, r.paths, "")
	if err != nil {
		return err
	}
	plaintext, err := a.credentialFactory(credential.SourcePlaintext, r.paths, "")
	if err != nil {
		return err
	}
	legacy := &credential.Stores{Keyring: keyring, Plaintext: plaintext}
	migrated, found, err := credential.MigrateLegacy(r.config.ControlURL, config.CredentialReference(r.paths, r.config.ProfileName), legacy, r.credentials)
	if err != nil {
		return fmt.Errorf("%w: %w", errLegacyMigration, err)
	}
	if !found {
		return nil
	}
	r.config.SelectedProfile.WorkspaceID = migrated.WorkspaceID
	if err := config.SaveProfile(r.paths, r.config.ProfileName, r.config.SelectedProfile, true); err != nil {
		return err
	}
	r.config.ProfileExists = true
	return nil
}
