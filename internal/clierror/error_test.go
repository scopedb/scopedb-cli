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

package clierror

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenderReportsUnderlyingCause(t *testing.T) {
	cause := errors.New("write credentials to OS keyring: exit status 1")
	err := Wrap(ExitGeneral, "login succeeded, but credentials could not be stored", cause)
	require.Equal(t, "Error: login succeeded, but credentials could not be stored\nCaused by: write credentials to OS keyring: exit status 1\n", Render(err))
}

func TestRenderDropsCauseThatRepeatsTheMessage(t *testing.T) {
	cause := errors.New("workspace not found")
	err := Wrap(ExitNotFound, "workspace not found", cause)
	require.Equal(t, "Error: workspace not found\n", Render(err))
}

func TestRenderOrdersCauseBeforeRequestIDAndHint(t *testing.T) {
	err := WithHint(Wrap(ExitAuth, "not logged in", errors.New("session token rejected")), "run 'scope login'")
	err.RequestID = "req-1"
	require.Equal(t, "Error: not logged in\nCaused by: session token rejected\nRequest ID: req-1\nHint: run 'scope login'\n", Render(err))
}

func TestRenderReportsPlainError(t *testing.T) {
	require.Equal(t, "Error: boom\n", Render(errors.New("boom")))
}

func TestWrapPreservesCause(t *testing.T) {
	cause := errors.New("underlying")
	err := Wrap(ExitGeneral, "outer", cause)
	require.ErrorIs(t, err, cause)
	require.Equal(t, ExitGeneral, ExitCode(err))
}
