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
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/scopedb/scopedb-cli/internal/output"
	"github.com/spf13/cobra"
)

type statusView struct {
	ControlURL            string `json:"control_url,omitempty"`
	Email                 string `json:"email,omitempty"`
	CredentialSource      string `json:"credential_source"`
	CredentialFile        string `json:"credential_file,omitempty"`
	UserStatus            string `json:"user_status,omitempty"`
	RefreshTokenExpiresAt string `json:"refresh_token_expires_at,omitempty"`
	WorkspaceID           string `json:"workspace_id,omitempty"`
	WorkspaceName         string `json:"workspace_name,omitempty"`
	Endpoint              string `json:"endpoint,omitempty"`
}

func (a *app) newStatusCommand() *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "status",
		Short: "Show authentication source, identity, and connection target",
		Long: "Show authentication source, identity, and connection target.\n" +
			"Uses environment credentials when set; otherwise verifies your CLI login.\n" +
			"Run 'scope doctor' to verify query access or 'scope workspace get' for deployment details.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return err
			}
			if access, active, machineErr := runtime.auth.MachineAccess(); active || machineErr != nil {
				if machineErr != nil {
					return machineErr
				}
				return renderStatus(a.out, format, statusView{
					CredentialSource: "environment", Endpoint: access.Endpoint,
				})
			}

			account, state, err := runtime.auth.Account(cmd.Context())
			if err != nil {
				return err
			}
			if account.SelectedWorkspaceID != "" && errors.Is(auth.RequireWorkspace(account), auth.ErrWorkspaceUnavailable) {
				if err := runtime.auth.SelectWorkspace(cmd.Context(), ""); err != nil {
					return err
				}
				account.SelectedWorkspaceID = ""
				if _, err := fmt.Fprintln(a.errOut, "The selected workspace is no longer available; no workspace is selected."); err != nil {
					return err
				}
			}
			view := statusView{
				ControlURL:            runtime.config.ControlURL,
				Email:                 account.User.Email,
				CredentialSource:      state.Source,
				UserStatus:            account.User.Status,
				RefreshTokenExpiresAt: refreshTokenExpiry(state.RefreshTokenExpiresAt),
				WorkspaceID:           account.SelectedWorkspaceID,
			}
			if state.Source == credential.SourcePlaintext {
				view.CredentialFile = runtime.paths.CredentialsFile
			}
			if account.SelectedWorkspaceID != "" {
				details, err := runtime.control.GetWorkspace(cmd.Context(), state.AccessToken, account.SelectedWorkspaceID)
				if err != nil {
					return err
				}
				view.WorkspaceName = details.Workspace.Name()
				view.Endpoint = details.Connection.APIBaseURL
			}
			if err := a.writeWorkspaceSetup(account); err != nil {
				return err
			}
			return renderStatus(a.out, format, view)
		},
	}
	command.Flags().StringVar(&format, "format", structuredFormatTable, "output format: table or json")
	return command
}

func refreshTokenExpiry(expiresAt time.Time) string {
	if expiresAt.IsZero() {
		return ""
	}
	return expiresAt.UTC().Format(time.RFC3339)
}

func renderStatus(out io.Writer, format string, view statusView) error {
	if format == structuredFormatJSON {
		return writeJSON(out, view)
	}
	t := output.NewTable("FIELD", "VALUE")
	t.AppendRow(table.Row{"Credential source", view.CredentialSource})
	if view.CredentialFile != "" {
		t.AppendRow(table.Row{"Credential file", view.CredentialFile})
	}
	t.AppendRows([]table.Row{
		{"Email", emptyDash(view.Email)},
		{"User status", emptyDash(view.UserStatus)},
		{"Refresh token expires", emptyDash(view.RefreshTokenExpiresAt)},
		{"Workspace", emptyDash(view.WorkspaceName)},
		{"Workspace ID", emptyDash(view.WorkspaceID)},
		{"Endpoint", emptyDash(view.Endpoint)},
		{"Control URL", emptyDash(view.ControlURL)},
	})
	return output.WriteTable(out, t)
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
