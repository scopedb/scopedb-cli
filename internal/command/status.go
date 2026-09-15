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
	"io"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

type statusView struct {
	AuthMode          string `json:"auth_mode"`
	ControlURL        string `json:"control_url,omitempty"`
	User              string `json:"user,omitempty"`
	UserStatus        string `json:"user_status,omitempty"`
	WorkspaceID       string `json:"workspace_id,omitempty"`
	WorkspaceName     string `json:"workspace_name,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	ProvisioningState string `json:"provisioning_state,omitempty"`
}

func (a *app) newStatusCommand() *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "status",
		Short: "Show authentication and workspace status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			if access, active, machineErr := runtime.auth.MachineAccess(); active || machineErr != nil {
				if machineErr != nil {
					return NormalizeError(machineErr)
				}
				return renderStatus(a.out, format, statusView{AuthMode: access.Mode, Endpoint: access.Endpoint})
			}

			state, session, err := runtime.auth.LoadSession(cmd.Context())
			if err != nil {
				return NormalizeError(err)
			}
			view := statusView{
				AuthMode:    "session",
				ControlURL:  runtime.config.ControlURL,
				User:        session.User.Email,
				UserStatus:  session.User.Status,
				WorkspaceID: state.WorkspaceID,
			}
			if state.WorkspaceID != "" {
				details, err := runtime.control.GetWorkspace(cmd.Context(), state.SessionToken, state.WorkspaceID)
				if err != nil {
					return NormalizeError(err)
				}
				view.WorkspaceName = details.Workspace.Name()
				view.Endpoint = details.Connection.APIBaseURL
				view.ProvisioningState = details.Provisioning.Status
			}
			if err := a.writeWorkspaceSetup(session); err != nil {
				return err
			}
			return renderStatus(a.out, format, view)
		},
	}
	command.Flags().StringVarP(&format, "format", "f", structuredFormatTable, "output format: table or json")
	return command
}

func renderStatus(out io.Writer, format string, view statusView) error {
	if format == structuredFormatJSON {
		return writeJSON(out, view)
	}
	t := newTable(out, "FIELD", "VALUE")
	t.AppendRows([]table.Row{
		{"Auth mode", view.AuthMode},
		{"User", emptyDash(view.User)},
		{"User status", emptyDash(view.UserStatus)},
		{"Workspace", emptyDash(view.WorkspaceName)},
		{"Workspace ID", emptyDash(view.WorkspaceID)},
		{"Endpoint", emptyDash(view.Endpoint)},
		{"Provisioning", emptyDash(view.ProvisioningState)},
		{"Control URL", emptyDash(view.ControlURL)},
	})
	t.Render()
	return nil
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
