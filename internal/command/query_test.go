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
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteResultFileDoesNotOverwriteByDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o600))
	err := writeResultFile(path, false, func(writer io.Writer) error {
		_, writeErr := io.WriteString(writer, "replacement")
		return writeErr
	})
	require.Error(t, err)
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "original", string(data))
}

func TestWriteResultFileRemovesPartialRender(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	wantErr := errors.New("render failed")
	err := writeResultFile(path, false, func(writer io.Writer) error {
		_, _ = io.WriteString(writer, "partial")
		return wantErr
	})
	require.ErrorIs(t, err, wantErr)
	assert.NoFileExists(t, path)
}
