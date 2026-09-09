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
	"os"
	"path/filepath"
	"runtime"

	"github.com/scopedb/scopedb-cli/internal/fileutil"
)

type plaintextDocument struct {
	Version  int              `json:"version"`
	Profiles map[string]State `json:"profiles"`
}

// PlaintextStore is an explicit fallback for hosts without a usable keyring.
// The file is permission-restricted but is not encrypted.
type PlaintextStore struct {
	path string
}

func NewPlaintextStore(path string) *PlaintextStore {
	return &PlaintextStore{path: path}
}

func (s *PlaintextStore) Load(controlURL string) (State, error) {
	document, err := s.read()
	if err != nil {
		return State{}, err
	}
	state, ok := document.Profiles[profileKey(controlURL)]
	if !ok {
		return State{}, ErrNotFound
	}
	if err := validate(controlURL, state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (s *PlaintextStore) Save(controlURL string, state State) error {
	document, err := s.read()
	if errors.Is(err, ErrNotFound) {
		document = plaintextDocument{Version: 1, Profiles: map[string]State{}}
	} else if err != nil {
		return err
	}
	if document.Profiles == nil {
		document.Profiles = map[string]State{}
	}
	document.Profiles[profileKey(controlURL)] = prepare(controlURL, state)
	return s.write(document)
}

func (s *PlaintextStore) Delete(controlURL string) error {
	document, err := s.read()
	if err != nil {
		return err
	}
	key := profileKey(controlURL)
	if _, ok := document.Profiles[key]; !ok {
		return ErrNotFound
	}
	delete(document.Profiles, key)
	return s.write(document)
}

func (s *PlaintextStore) read() (plaintextDocument, error) {
	info, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return plaintextDocument{}, ErrNotFound
	}
	if err != nil {
		return plaintextDocument{}, fmt.Errorf("inspect plaintext credential file: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return plaintextDocument{}, fmt.Errorf("plaintext credential file %s has unsafe permissions %03o; expected 600", s.path, info.Mode().Perm())
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return plaintextDocument{}, fmt.Errorf("read plaintext credentials: %w", err)
	}
	var document plaintextDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return plaintextDocument{}, fmt.Errorf("decode plaintext credentials: %w", err)
	}
	if document.Version != 1 {
		return plaintextDocument{}, fmt.Errorf("unsupported plaintext credential file version %d", document.Version)
	}
	return document, nil
}

func (s *PlaintextStore) write(document plaintextDocument) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create credential directory: %w", err)
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("encode plaintext credentials: %w", err)
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".scope-credentials-*")
	if err != nil {
		return fmt.Errorf("create temporary credential file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("set credential file permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary credential file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary credential file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary credential file: %w", err)
	}
	if err := fileutil.Commit(temporaryPath, s.path, true); err != nil {
		return fmt.Errorf("replace plaintext credential file: %w", err)
	}
	return nil
}
