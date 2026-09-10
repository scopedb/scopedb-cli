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
)

func TestWriteResultFileDoesNotOverwriteByDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeResultFile(path, false, func(writer io.Writer) error {
		_, writeErr := io.WriteString(writer, "replacement")
		return writeErr
	})
	if err == nil {
		t.Fatal("writeResultFile() error = nil")
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if got, want := string(data), "original"; got != want {
		t.Errorf("file = %q, want %q", got, want)
	}
}

func TestWriteResultFileRemovesPartialRender(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	wantErr := errors.New("render failed")
	err := writeResultFile(path, false, func(writer io.Writer) error {
		_, _ = io.WriteString(writer, "partial")
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("writeResultFile() error = %v, want %v", err, wantErr)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Stat() error = %v, want not exist", statErr)
	}
}
