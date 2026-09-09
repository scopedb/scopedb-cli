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
	"context"
	"errors"
	"io"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/spf13/cobra"
)

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Details string `json:"details"`
}

type doctorReport struct {
	OK     bool          `json:"ok"`
	Checks []doctorCheck `json:"checks"`
}

func (a *app) newDoctorCommand() *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "doctor",
		Short: "Check local configuration and ScopeDB connectivity",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			runtime, err := a.runtime(command)
			if err != nil {
				return NormalizeError(err)
			}
			report := doctorReport{OK: true, Checks: []doctorCheck{
				{Name: "configuration", Status: "pass", Details: runtime.paths.Config},
				{Name: "credential store", Status: "pass", Details: runtime.config.CredentialStore},
			}}

			healthCtx, cancel := context.WithTimeout(command.Context(), 5*time.Second)
			healthErr := runtime.control.Health(healthCtx)
			cancel()
			if healthErr != nil {
				report.OK = false
				report.Checks = append(report.Checks, doctorCheck{Name: "control plane", Status: "fail", Details: healthErr.Error()})
			} else {
				report.Checks = append(report.Checks, doctorCheck{Name: "control plane", Status: "pass", Details: runtime.config.ControlURL})
			}

			access, machine, machineErr := runtime.auth.MachineAccess()
			switch {
			case machineErr != nil:
				report.OK = false
				report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "fail", Details: machineErr.Error()})
			case machine:
				report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "pass", Details: "API key from environment for " + access.Endpoint})
			default:
				state, loadErr := runtime.credentials.Load(runtime.config.ControlURL)
				if errors.Is(loadErr, credential.ErrNotFound) {
					report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "warn", Details: "not logged in"})
				} else if loadErr != nil {
					report.OK = false
					report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "fail", Details: loadErr.Error()})
				} else {
					sessionCtx, sessionCancel := context.WithTimeout(command.Context(), 5*time.Second)
					session, sessionErr := runtime.control.GetSession(sessionCtx, state.SessionToken)
					sessionCancel()
					if sessionErr != nil {
						report.OK = false
						report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "fail", Details: sessionErr.Error()})
					} else {
						report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "pass", Details: session.User.Email + " / " + session.CurrentWorkspaceID})
					}
				}
			}

			if err := renderDoctor(a.out, format, report); err != nil {
				return NormalizeError(err)
			}
			if !report.OK {
				return clierror.New(clierror.ExitGeneral, "one or more checks failed")
			}
			return nil
		},
	}
	command.Flags().StringVarP(&format, "format", "f", structuredFormatTable, "output format: table or json")
	return command
}

func renderDoctor(out io.Writer, format string, report doctorReport) error {
	if format == structuredFormatJSON {
		return writeJSON(out, report)
	}
	t := newTable(out, "CHECK", "STATUS", "DETAILS")
	for _, check := range report.Checks {
		t.AppendRow(table.Row{check.Name, check.Status, check.Details})
	}
	t.Render()
	return nil
}
