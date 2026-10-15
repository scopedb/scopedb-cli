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

// Package filelock serializes credential refresh across CLI processes.
package filelock

import (
	"context"
	"time"
)

// Lock is an exclusive advisory lock on a file. Close releases it and is safe to
// call more than once.
type Lock interface {
	Close() error
}

// lockRetryInterval is how often a non-blocking acquire attempt retries while another process holds
// the lock.
const lockRetryInterval = 50 * time.Millisecond

// Acquire waits for the exclusive lock on path, creating the file if it does not exist, and gives up
// when the context ends. Callers must Close the returned lock.
func Acquire(ctx context.Context, path string) (Lock, error) {
	return acquire(ctx, path)
}
