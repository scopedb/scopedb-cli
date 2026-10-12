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
	"fmt"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/spf13/cobra"
)

func (a *app) newWorkspaceCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "workspace",
		Short: "Inspect or select a workspace",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	command.AddCommand(
		a.newWorkspaceListCommand(),
		a.newWorkspaceUseCommand(),
		a.newWorkspaceGetCommand(),
	)
	return command
}

func (a *app) newWorkspaceListCommand() *cobra.Command {
	var format string
	var limit int
	command := &cobra.Command{
		Use:   "list",
		Short: "List available workspaces",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			if err := validateListLimit(limit); err != nil {
				return err
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			_, session, err := runtime.auth.LoadSession(cmd.Context())
			if err != nil {
				return NormalizeError(err)
			}
			workspaces := limitedResults(session.Workspaces, limit)
			views := make([]workspaceListItem, 0, len(workspaces))
			for _, workspace := range workspaces {
				views = append(views, workspaceListItem{
					ID:          workspace.ID,
					DisplayName: workspace.DisplayName,
					Current:     workspace.ID == session.CurrentWorkspaceID,
				})
			}
			// Choosing a workspace is what this command enables, so a missing
			// selection needs no notice; only an empty account cannot be listed.
			if len(session.Workspaces) == 0 {
				if err := a.writeWorkspaceSetup(session); err != nil {
					return err
				}
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, views)
			}
			t := newTable(a.out, "CURRENT", "NAME", "ID")
			for index, workspace := range workspaces {
				current := ""
				if views[index].Current {
					current = "*"
				}
				t.AppendRow(table.Row{current, workspace.Name(), workspace.ID})
			}
			t.Render()
			return nil
		},
	}
	command.Flags().StringVar(&format, "format", structuredFormatTable, "output format: table or json")
	command.Flags().IntVarP(&limit, "limit", "L", 0, "maximum results to display (0 means all)")
	return command
}

type workspaceListItem struct {
	ID          string  `json:"id"`
	DisplayName *string `json:"display_name"`
	Current     bool    `json:"current"`
}

func (a *app) newWorkspaceUseCommand() *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "use <id-or-name>",
		Short: "Select the workspace for your login session",
		Long: "Select the workspace for your login session.\n" +
			"Data commands use SCOPEDB_ENDPOINT and SCOPEDB_API_KEY when set, regardless of this selection.",
		Args: exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTextFormat(format); err != nil {
				return err
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			state, session, err := runtime.auth.LoadSession(cmd.Context())
			if err != nil {
				return NormalizeError(err)
			}
			if len(session.Workspaces) == 0 {
				return NormalizeError(auth.RequireWorkspace(session))
			}
			workspace, err := resolveWorkspace(session.Workspaces, args[0])
			if err != nil {
				return err
			}
			changed := workspace.ID != session.CurrentWorkspaceID
			if changed {
				if err := runtime.auth.SelectWorkspace(cmd.Context(), state, workspace.ID); err != nil {
					return NormalizeError(err)
				}
			}
			if _, active, machineErr := runtime.auth.MachineAccess(); machineErr != nil {
				if _, err := fmt.Fprintln(a.errOut, "Warning: data commands require both SCOPEDB_ENDPOINT and SCOPEDB_API_KEY; set both or unset both to use your login workspace."); err != nil {
					return NormalizeError(err)
				}
			} else if active {
				if _, err := fmt.Fprintln(a.errOut, "Warning: data commands still use SCOPEDB_ENDPOINT and SCOPEDB_API_KEY from the environment; unset both to use your login workspace."); err != nil {
					return NormalizeError(err)
				}
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, workspaceUseResult{ID: workspace.ID, DisplayName: workspace.DisplayName, Changed: changed})
			}
			if !changed {
				_, err := fmt.Fprintf(a.out, "Already using workspace %s (%s) for your login session.\n", workspace.Name(), workspace.ID)
				return NormalizeError(err)
			}
			_, err = fmt.Fprintf(a.out, "Now using workspace %s (%s) for your login session.\n", workspace.Name(), workspace.ID)
			return NormalizeError(err)
		},
	}
	command.Flags().StringVar(&format, "format", structuredFormatText, "output format: text or json")
	return command
}

type workspaceUseResult struct {
	ID          string  `json:"id"`
	DisplayName *string `json:"display_name"`
	Changed     bool    `json:"changed"`
}

type workspaceView struct {
	Workspace struct {
		ID          string  `json:"id"`
		DisplayName *string `json:"display_name"`
	} `json:"workspace"`
	Connection struct {
		Endpoint   string `json:"endpoint"`
		AuthScheme string `json:"auth_scheme"`
	} `json:"connection"`
	Placement struct {
		Provider string `json:"provider"`
		Region   string `json:"region"`
	} `json:"placement"`
	Provisioning struct {
		Status    string     `json:"status"`
		UpdatedAt *time.Time `json:"updated_at"`
	} `json:"provisioning"`
}

func (a *app) newWorkspaceGetCommand() *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "get",
		Short: "Get details of your login session's current workspace",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			state, err := runtime.auth.LoadWorkspaceSession(cmd.Context())
			if err != nil {
				return NormalizeError(err)
			}
			details, err := runtime.control.GetWorkspace(cmd.Context(), state.SessionToken, state.WorkspaceID)
			if err != nil {
				return NormalizeError(err)
			}
			if format == structuredFormatJSON {
				var view workspaceView
				view.Workspace.ID = details.Workspace.ID
				view.Workspace.DisplayName = details.Workspace.DisplayName
				view.Connection.Endpoint = details.Connection.APIBaseURL
				view.Connection.AuthScheme = details.Connection.AuthScheme
				view.Placement.Provider = details.Placement.Provider
				view.Placement.Region = details.Placement.Region
				view.Provisioning.Status = details.Provisioning.Status
				view.Provisioning.UpdatedAt = details.Provisioning.UpdatedAt
				return writeJSON(a.out, view)
			}
			t := newTable(a.out, "FIELD", "VALUE")
			t.AppendRows([]table.Row{
				{"Name", details.Workspace.Name()},
				{"ID", details.Workspace.ID},
				{"Status", details.Provisioning.Status},
				{"Provider", emptyDash(details.Placement.Provider)},
				{"Region", emptyDash(details.Placement.Region)},
				{"Endpoint", emptyDash(details.Connection.APIBaseURL)},
				{"Auth scheme", emptyDash(details.Connection.AuthScheme)},
			})
			t.Render()
			return nil
		},
	}
	command.Flags().StringVar(&format, "format", structuredFormatTable, "output format: table or json")
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
