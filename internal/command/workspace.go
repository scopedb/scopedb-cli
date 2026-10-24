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
	"io"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/output"
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
				return err
			}
			account, _, err := runtime.auth.Account(cmd.Context())
			if err != nil {
				return err
			}
			workspaces := limitedResults(account.Workspaces, limit)
			// Choosing a workspace is what this command enables, so a missing
			// selection needs no notice; only an empty account cannot be listed.
			if len(account.Workspaces) == 0 {
				if err := a.writeWorkspaceSetup(account); err != nil {
					return err
				}
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, workspaceListItems(workspaces, account.SelectedWorkspaceID))
			}
			return writeWorkspaceListTable(a.out, workspaces, account.SelectedWorkspaceID)
		},
	}
	command.Flags().StringVar(&format, "format", structuredFormatTable, "output format: table or json")
	command.Flags().IntVarP(&limit, "limit", "L", 0, "maximum results to display (0 means all)")
	return command
}

type workspaceListItem struct {
	ID          string  `json:"id"`
	DisplayName *string `json:"display_name"`
	Status      string  `json:"status"`
	Current     bool    `json:"current"`
}

func workspaceListItemFor(workspace controlplane.Workspace, current bool) workspaceListItem {
	return workspaceListItem{
		ID:          workspace.ID,
		DisplayName: workspace.DisplayName,
		Status:      workspaceStatus(workspace),
		Current:     current,
	}
}

func workspaceListItems(workspaces []controlplane.Workspace, selectedID string) []workspaceListItem {
	views := make([]workspaceListItem, 0, len(workspaces))
	for _, workspace := range workspaces {
		views = append(views, workspaceListItemFor(workspace, workspace.ID == selectedID))
	}
	return views
}

func writeWorkspaceListTable(out io.Writer, workspaces []controlplane.Workspace, selectedID string) error {
	t := output.NewTable("CURRENT", "NAME", "ID", "STATUS")
	for _, workspace := range workspaces {
		current := ""
		if workspace.ID == selectedID {
			current = "*"
		}
		t.AppendRow(table.Row{current, workspace.Name(), workspace.ID, workspaceStatus(workspace)})
	}
	return output.WriteTable(out, t)
}

func workspaceStatus(workspace controlplane.Workspace) string {
	if workspace.ScheduledForDeletion() {
		return "scheduled for deletion"
	}
	return workspace.ProvisioningStatus
}

func (a *app) newWorkspaceUseCommand() *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "use <id-or-name>",
		Short: "Select the workspace for this login",
		Long: "Select the workspace for this login.\n" +
			"Data commands use SCOPEDB_ENDPOINT and SCOPEDB_API_KEY when set, regardless of this selection.",
		Args: exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTextFormat(format); err != nil {
				return err
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return err
			}
			account, _, err := runtime.auth.Account(cmd.Context())
			if err != nil {
				return err
			}
			if len(account.Workspaces) == 0 {
				return auth.RequireWorkspace(account)
			}
			workspace, err := resolveWorkspace(account.Workspaces, args[0])
			if err != nil {
				return err
			}
			if workspace.ScheduledForDeletion() {
				return clierror.WithHint(
					clierror.New(clierror.ExitUsage, fmt.Sprintf("workspace %s (%s) is scheduled for deletion", workspace.Name(), workspace.ID)),
					"restore it in the Console before selecting it",
				)
			}
			changed := workspace.ID != account.SelectedWorkspaceID
			if changed {
				if err := runtime.auth.SelectWorkspace(cmd.Context(), workspace.ID); err != nil {
					return err
				}
			}
			if _, active, machineErr := runtime.auth.MachineAccess(); machineErr != nil {
				if _, err := fmt.Fprintln(a.errOut, "Warning: data commands require both SCOPEDB_ENDPOINT and SCOPEDB_API_KEY; set both or unset both to use your login workspace."); err != nil {
					return err
				}
			} else if active {
				if _, err := fmt.Fprintln(a.errOut, "Warning: data commands still use SCOPEDB_ENDPOINT and SCOPEDB_API_KEY from the environment; unset both to use your login workspace."); err != nil {
					return err
				}
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, workspaceUseResult{ID: workspace.ID, DisplayName: workspace.DisplayName, Changed: changed})
			}
			if !changed {
				_, err := fmt.Fprintf(a.out, "Already using workspace %s (%s) for this login.\n", workspace.Name(), workspace.ID)
				return err
			}
			_, err = fmt.Fprintf(a.out, "Now using workspace %s (%s) for this login.\n", workspace.Name(), workspace.ID)
			return err
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
		Short: "Get details of the selected workspace",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return err
			}
			state, err := runtime.auth.LoadWorkspaceAccess(cmd.Context())
			if err != nil {
				return err
			}
			details, err := runtime.control.GetWorkspace(cmd.Context(), state.AccessToken, state.WorkspaceID)
			if err != nil {
				return err
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
			t := output.NewTable("FIELD", "VALUE")
			t.AppendRows([]table.Row{
				{"Name", details.Workspace.Name()},
				{"ID", details.Workspace.ID},
				{"Status", details.Provisioning.Status},
				{"Provider", emptyDash(details.Placement.Provider)},
				{"Region", emptyDash(details.Placement.Region)},
				{"Endpoint", emptyDash(details.Connection.APIBaseURL)},
				{"Auth scheme", emptyDash(details.Connection.AuthScheme)},
			})
			return output.WriteTable(a.out, t)
		},
	}
	command.Flags().StringVar(&format, "format", structuredFormatTable, "output format: table or json")
	return command
}

func workspaceByID(workspaces []controlplane.Workspace, id string) (controlplane.Workspace, bool) {
	for _, workspace := range workspaces {
		if workspace.ID == id {
			return workspace, true
		}
	}
	return controlplane.Workspace{}, false
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
