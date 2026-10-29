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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func validWorkload() State {
	return State{
		Version:         currentStateVersion,
		ControlURL:      "https://control.example.com",
		Kind:            KindWorkload,
		WorkspaceID:     "ws-1",
		Endpoint:        "https://data.example.com",
		APIKey:          "sk_workload",
		APIKeyExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
}

func TestValidateWorkloadState(t *testing.T) {
	require.NoError(t, validate("https://control.example.com", validWorkload()))

	for _, mutate := range []func(*State){
		func(s *State) { s.APIKey = "" },
		func(s *State) { s.Endpoint = "" },
		func(s *State) { s.WorkspaceID = "" },
	} {
		state := validWorkload()
		mutate(&state)
		require.ErrorIs(t, validate("https://control.example.com", state), ErrInvalidState)
	}
}

func TestValidateWorkloadNeedsNoOAuthTokens(t *testing.T) {
	state := validWorkload()
	require.NoError(t, validate("https://control.example.com", state),
		"a workload credential has no access or refresh token")
}

func TestValidateRejectsOAuthWithoutTokens(t *testing.T) {
	state := State{Version: currentStateVersion, ControlURL: "https://control.example.com"}
	require.ErrorIs(t, validate("https://control.example.com", state), ErrInvalidState)

	state.AccessToken = "oat"
	require.ErrorIs(t, validate("https://control.example.com", state), ErrInvalidState,
		"an OAuth login still requires a refresh token")
}

func TestValidateRejectsAnUnknownKind(t *testing.T) {
	state := State{
		Version: currentStateVersion, ControlURL: "https://control.example.com",
		Kind: "browser", AccessToken: "oat", RefreshToken: "ort",
	}
	require.ErrorIs(t, validate("https://control.example.com", state), ErrInvalidState)
}

func TestValidateClearedTombstone(t *testing.T) {
	state := State{Version: currentStateVersion, ControlURL: "https://control.example.com", Cleared: true}
	require.NoError(t, validate("https://control.example.com", state))
}
