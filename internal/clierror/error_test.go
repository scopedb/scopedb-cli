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

type wrapper struct {
	message string
	err     error
}

func (w wrapper) Error() string { return w.message }
func (w wrapper) Unwrap() error { return w.err }

func TestCauseReachesDetailBelowARepetitiveWrapper(t *testing.T) {
	transport := errors.New("Post \"https://control.example/api/login\": dial tcp: connection refused")
	err := Wrap(ExitTemporary, "cannot reach ScopeDB control plane", wrapper{message: "cannot reach ScopeDB control plane", err: transport})
	require.Equal(t, transport.Error(), err.cause())
}

func TestRenderPrintsCauseBeforeRequestIDAndHint(t *testing.T) {
	err := WithHint(Wrap(ExitAuth, "not logged in", errors.New("session token rejected")), "run 'scope login'")
	err.RequestID = "req-1"
	require.Equal(t, "Error: not logged in\nCaused by: session token rejected\nRequest ID: req-1\nHint: run 'scope login'\n", Render(err))
}

func TestRenderOmitsCauseWhenMessageRepeatsIt(t *testing.T) {
	err := Wrap(ExitNotFound, "workspace not found", errors.New("workspace not found"))
	require.Equal(t, "Error: workspace not found\n", Render(err))
}

func TestRenderOmitsCauseWithoutUnderlyingFailure(t *testing.T) {
	require.Equal(t, "Error: email must not be empty\n", Render(New(ExitUsage, "email must not be empty")))
}

func TestRenderKeepsJoinedCauseOnOneLine(t *testing.T) {
	err := Wrap(ExitGeneral, "login succeeded, but credentials could not be stored", errors.New("write credentials to OS keyring: exit status 1"))
	err.Message += " and previous credentials could not be restored"
	err.Err = errors.Join(err.Err, errors.New("restore previous credentials: permission denied"))
	require.Equal(t, "Error: login succeeded, but credentials could not be stored and previous credentials could not be restored\n"+
		"Caused by: write credentials to OS keyring: exit status 1; restore previous credentials: permission denied\n", Render(err))
}

func TestCompactJoinsPartsInOrder(t *testing.T) {
	err := WithHint(Wrap(ExitAuth, "not logged in", errors.New("session token rejected")), "run 'scope login'")
	err.RequestID = "req-1"
	require.Equal(t, "not logged in; session token rejected; request ID: req-1; run 'scope login'", Compact(err))
}

func TestCompactOfPlainErrorIsItsMessage(t *testing.T) {
	require.Equal(t, "boom", Compact(errors.New("boom")))
}
