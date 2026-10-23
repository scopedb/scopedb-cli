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

package filelock

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAcquireTakesAnUncontendedLock(t *testing.T) {
	lock, err := Acquire(context.Background(), filepath.Join(t.TempDir(), "credentials.lock"))
	require.NoError(t, err)
	require.NoError(t, lock.Close())
}

func TestAcquireGivesUpWhenTheContextEnds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.lock")
	held, err := Acquire(context.Background(), path)
	require.NoError(t, err)
	defer func() { require.NoError(t, held.Close()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = Acquire(ctx, path)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
