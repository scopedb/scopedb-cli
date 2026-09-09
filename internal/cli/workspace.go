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

package cli

import (
	"fmt"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/spf13/cobra"
)

func (a *app) newWorkspaceCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "workspace",
		Short: "Inspect or select a workspace",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	command.AddCommand(
		a.newWorkspaceListCommand(),
		a.newWorkspaceUseCommand(),
		a.newWorkspaceShowCommand(),
	)
	return command
}

func (a *app) newWorkspaceListCommand() *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "list",
		Short: "List available workspaces",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			runtime, err := a.runtime(command)
			if err != nil {
				return NormalizeError(err)
			}
			_, session, err := runtime.auth.LoadSession(command.Context())
			if err != nil {
				return NormalizeError(err)
			}
			views := make([]workspaceListItem, 0, len(session.Workspaces))
			for _, workspace := range session.Workspaces {
				views = append(views, workspaceListItem{
					ID:          workspace.ID,
					DisplayName: workspace.DisplayName,
					Role:        workspace.Role,
					Current:     workspace.ID == session.CurrentWorkspaceID,
				})
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, views)
			}
			t := newTable(a.out, "CURRENT", "NAME", "ID", "ROLE")
			for index, workspace := range session.Workspaces {
				current := ""
				if views[index].Current {
					current = "*"
				}
				t.AppendRow(table.Row{current, workspace.Name(), workspace.ID, workspace.Role})
			}
			t.Render()
			return nil
		},
	}
	command.Flags().StringVarP(&format, "format", "f", structuredFormatTable, "output format: table or json")
	return command
}

type workspaceListItem struct {
	ID          string  `json:"id"`
	DisplayName *string `json:"display_name"`
	Role        string  `json:"role"`
	Current     bool    `json:"current"`
}

func (a *app) newWorkspaceUseCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "use <id-or-name>",
		Short: "Select the workspace used by subsequent commands",
		Args:  exactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			runtime, err := a.runtime(command)
			if err != nil {
				return NormalizeError(err)
			}
			state, session, err := runtime.auth.LoadSession(command.Context())
			if err != nil {
				return NormalizeError(err)
			}
			workspace, err := resolveWorkspace(session.Workspaces, args[0])
			if err != nil {
				return err
			}
			if workspace.ID == session.CurrentWorkspaceID {
				_, err := fmt.Fprintf(a.out, "Already using workspace %s (%s).\n", workspace.Name(), workspace.ID)
				return NormalizeError(err)
			}
			if err := runtime.auth.SelectWorkspace(command.Context(), state, workspace.ID); err != nil {
				return NormalizeError(err)
			}
			_, err = fmt.Fprintf(a.out, "Now using workspace %s (%s).\n", workspace.Name(), workspace.ID)
			return NormalizeError(err)
		},
	}
}

func (a *app) newWorkspaceShowCommand() *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "show",
		Short: "Show the current workspace",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			runtime, err := a.runtime(command)
			if err != nil {
				return NormalizeError(err)
			}
			state, _, err := runtime.auth.LoadSession(command.Context())
			if err != nil {
				return NormalizeError(err)
			}
			details, err := runtime.control.GetWorkspace(command.Context(), state.SessionToken, state.WorkspaceID)
			if err != nil {
				return NormalizeError(err)
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, details)
			}
			t := newTable(a.out, "FIELD", "VALUE")
			t.AppendRows([]table.Row{
				{"Name", details.Workspace.Name()},
				{"ID", details.Workspace.ID},
				{"Role", details.Workspace.Role},
				{"Status", details.Provisioning.Status},
				{"Provider", emptyDash(details.Placement.Provider)},
				{"Region", emptyDash(details.Placement.Region)},
				{"Endpoint", emptyDash(details.Connection.APIBaseURL)},
				{"Auth scheme", emptyDash(details.Connection.AuthScheme)},
				{"Reason", optionalString(details.Provisioning.Reason)},
			})
			t.Render()
			return nil
		},
	}
	command.Flags().StringVarP(&format, "format", "f", structuredFormatTable, "output format: table or json")
	return command
}

func resolveWorkspace(workspaces []controlplane.Workspace, value string) (controlplane.Workspace, error) {
	value = strings.TrimSpace(value)
	for _, workspace := range workspaces {
		if workspace.ID == value {
			return workspace, nil
		}
	}
	var matches []controlplane.Workspace
	for _, workspace := range workspaces {
		if workspace.DisplayName != nil && strings.EqualFold(*workspace.DisplayName, value) {
			matches = append(matches, workspace)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return controlplane.Workspace{}, clierror.New(clierror.ExitNotFound, fmt.Sprintf("workspace %q was not found", value))
	default:
		return controlplane.Workspace{}, usageError(fmt.Sprintf("workspace name %q is ambiguous; use its ID", value))
	}
}
