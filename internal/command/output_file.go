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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/fileutil"
)

func writeResultFile(path string, force bool, render func(io.Writer) error) error {
	if path == "" {
		return errors.New("output path must not be empty")
	}
	if _, err := os.Stat(path); err == nil && !force {
		return clierror.WithHint(clierror.New(clierror.ExitGeneral, fmt.Sprintf("output file %s already exists", path)), "pass --force to overwrite it")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output file: %w", err)
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".scope-result-*")
	if err != nil {
		return fmt.Errorf("create temporary output file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set output file permissions: %w", err)
	}
	if err := render(temporary); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync output file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close output file: %w", err)
	}
	if err := fileutil.Commit(temporaryPath, path, force); err != nil {
		if !force && errors.Is(err, os.ErrExist) {
			return clierror.WithHint(clierror.New(clierror.ExitGeneral, fmt.Sprintf("output file %s was created concurrently", path)), "choose another path or pass --force")
		}
		return fmt.Errorf("replace output file: %w", err)
	}
	return nil
}
