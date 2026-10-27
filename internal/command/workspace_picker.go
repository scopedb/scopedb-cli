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
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/spf13/cobra"
)

func eligibleWorkspaces(workspaces []controlplane.Workspace) []controlplane.Workspace {
	var eligible []controlplane.Workspace
	for _, workspace := range workspaces {
		if !workspace.ScheduledForDeletion() {
			eligible = append(eligible, workspace)
		}
	}
	return eligible
}

func (a *app) pickWorkspace(ctx context.Context, workspaces []controlplane.Workspace) (controlplane.Workspace, error) {
	if !a.isInputTerminal() || !a.isErrorTerminal() {
		return controlplane.Workspace{}, usageError("workspace ID is required without an interactive terminal; run 'scope workspace list'")
	}
	eligible := eligibleWorkspaces(workspaces)
	if len(eligible) == 0 {
		return controlplane.Workspace{}, usageError("no eligible workspace is available")
	}
	for i, workspace := range eligible {
		if _, err := fmt.Fprintf(a.errOut, "%d. %s (%s)\n", i+1, workspace.Name(), workspace.ID); err != nil {
			return controlplane.Workspace{}, err
		}
	}
	for {
		if _, err := fmt.Fprint(a.errOut, "Select a workspace number (empty to cancel): "); err != nil {
			return controlplane.Workspace{}, err
		}
		line, err := a.readLine(ctx, "")
		if err != nil && !errors.Is(err, io.EOF) {
			return controlplane.Workspace{}, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return controlplane.Workspace{}, usageError("workspace selection cancelled; no workspace was changed")
		}
		number, parseErr := strconv.Atoi(line)
		if parseErr == nil && number > 0 && number <= len(eligible) {
			return eligible[number-1], nil
		}
		if errors.Is(err, io.EOF) {
			return controlplane.Workspace{}, usageError("invalid workspace selection; no workspace was changed")
		}
		if _, err := fmt.Fprintln(a.errOut, "Enter one of the displayed numbers."); err != nil {
			return controlplane.Workspace{}, err
		}
	}
}

func (a *app) completeWorkspaces(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
	if cmd.CommandPath() == "scope workspace use" && len(args) != 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
	defer cancel()
	runtime, err := a.runtime(cmd)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	account, _, err := runtime.auth.Account(ctx)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	var matches []string
	for _, workspace := range eligibleWorkspaces(account.Workspaces) {
		if strings.HasPrefix(workspace.ID, prefix) {
			matches = append(matches, workspace.ID+"\t"+strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(workspace.Name()))
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}
