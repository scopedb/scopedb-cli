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
	"strings"

	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/spf13/cobra"
)

func requestedWorkspace(cmd *cobra.Command, value string) (string, error) {
	value = strings.TrimSpace(value)
	if flag := cmd.Flag("workspace"); flag != nil && flag.Changed && value == "" {
		return "", usageError("--workspace must not be empty")
	}
	return value, nil
}

func (a *app) loadWorkspaceSession(cmd *cobra.Command, runtime *runtimeContext, requested string) (credential.State, error) {
	if requested == "" {
		return runtime.auth.LoadWorkspaceSession(cmd.Context())
	}
	state, session, err := runtime.auth.LoadSession(cmd.Context())
	if err != nil {
		return credential.State{}, err
	}
	if session.User.Status == "pending" {
		return credential.State{}, auth.ErrApprovalRequired
	}
	if len(session.Workspaces) == 0 {
		return credential.State{}, auth.ErrNoWorkspaces
	}
	workspace, err := resolveWorkspace(session.Workspaces, requested)
	if err != nil {
		return credential.State{}, err
	}
	state.WorkspaceID = workspace.ID
	return state, nil
}

func (a *app) resolveDataAccess(cmd *cobra.Command, runtime *runtimeContext, requested string) (auth.Access, error) {
	if requested == "" {
		return runtime.auth.ResolveDataAccess(cmd.Context())
	}
	if _, machine, err := runtime.auth.MachineAccess(); machine || err != nil {
		if err != nil {
			return auth.Access{}, err
		}
		return auth.Access{}, usageError("--workspace cannot be combined with SCOPEDB_ENDPOINT and SCOPEDB_API_KEY")
	}
	state, err := a.loadWorkspaceSession(cmd, runtime, requested)
	if err != nil {
		return auth.Access{}, err
	}
	return runtime.auth.ResolveDataAccessForWorkspace(cmd.Context(), state)
}
