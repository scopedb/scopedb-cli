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

//go:build windows

package filelock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

type winlock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquire(ctx context.Context, path string) (Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open credential lock: %w", err)
	}
	lock := &winlock{file: file}
	handle := windows.Handle(file.Fd())
	// The attempts are non-blocking so the wait stays interruptible: a blocking LockFileEx cannot
	// observe the context, which would hang the process past Ctrl+C behind a wedged holder.
	for {
		lock.overlapped = windows.Overlapped{}
		err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock.overlapped)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			_ = file.Close()
			return nil, fmt.Errorf("lock credentials: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, fmt.Errorf("wait for the credential lock: %w", ctx.Err())
		case <-time.After(lockRetryInterval):
		}
	}
}

func (l *winlock) Close() error {
	if l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	unlockErr := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &l.overlapped)
	closeErr := file.Close()
	if unlockErr != nil {
		return fmt.Errorf("unlock credentials: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close credential lock: %w", closeErr)
	}
	return nil
}
