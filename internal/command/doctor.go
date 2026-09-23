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
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/scopedb/scopedb-cli/internal/auth"
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

const doctorStatement = "SELECT 1 AS ready"

func (a *app) newDoctorCommand() *cobra.Command {
	var format string
	var timeout time.Duration
	command := &cobra.Command{
		Use:   "doctor",
		Short: "Check local configuration and ScopeDB connectivity",
		Long: "Check configuration, authentication, and connectivity by running SELECT 1 AS ready.\n" +
			"Uses SCOPEDB_ENDPOINT and SCOPEDB_API_KEY when both are set; otherwise uses your login.\n" +
			"Incomplete account setup is reported as a warning without running a query.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			if timeout <= 0 {
				return usageError("--timeout must be positive")
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			report := doctorReport{OK: true, Checks: []doctorCheck{
				{Name: "configuration", Status: "pass", Details: runtime.paths.Config},
				{Name: "credential store", Status: "pass", Details: runtime.config.CredentialStore},
			}}

			access, machine, machineErr := runtime.auth.MachineAccess()
			switch {
			case machineErr != nil:
				report.OK = false
				report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "fail", Details: machineErr.Error()})
			case machine:
				report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "pass", Details: "API key from environment for " + access.Endpoint})
				a.checkDoctorDataPlane(cmd.Context(), runtime, timeout, &report)
			default:
				healthCtx, cancel := context.WithTimeout(cmd.Context(), timeout)
				healthErr := runtime.control.Health(healthCtx)
				cancel()
				if healthErr != nil {
					report.OK = false
					report.Checks = append(report.Checks, doctorCheck{Name: "control plane", Status: "fail", Details: doctorErrorDetails(healthErr)})
				} else {
					report.Checks = append(report.Checks, doctorCheck{Name: "control plane", Status: "pass", Details: runtime.config.ControlURL})
				}

				state, loadErr := runtime.credentials.Load(runtime.config.ControlURL)
				if errors.Is(loadErr, credential.ErrNotFound) {
					report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "warn", Details: "not logged in; run 'scope login' or set SCOPEDB_ENDPOINT and SCOPEDB_API_KEY"})
				} else if loadErr != nil {
					report.OK = false
					report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "fail", Details: loadErr.Error()})
				} else {
					sessionCtx, sessionCancel := context.WithTimeout(cmd.Context(), timeout)
					session, sessionErr := runtime.control.GetSession(sessionCtx, state.SessionToken)
					sessionCancel()
					if sessionErr != nil {
						report.OK = false
						report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "fail", Details: doctorErrorDetails(sessionErr)})
					} else {
						report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "pass", Details: session.User.Email})
						if setupErr := workspaceSetupError(auth.RequireWorkspace(session)); setupErr != nil {
							report.Checks = append(report.Checks, doctorCheck{Name: "workspace", Status: "warn", Details: fmt.Sprintf("%s; %s", setupErr.Message, setupErr.Hint)})
						} else {
							report.Checks = append(report.Checks, doctorCheck{Name: "workspace", Status: "pass", Details: session.CurrentWorkspaceID})
							a.checkDoctorDataPlane(cmd.Context(), runtime, timeout, &report)
						}
					}
				}
			}

			if err := cmd.Context().Err(); err != nil {
				return NormalizeError(err)
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
	command.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "maximum time for each remote check, including credential resolution for the query")
	return command
}

func (a *app) checkDoctorDataPlane(ctx context.Context, runtime *runtimeContext, timeout time.Duration, report *doctorReport) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	access, err := runtime.auth.ResolveDataAccess(ctx)
	if err == nil {
		_, err = a.query.Execute(ctx, access, doctorStatement)
	}
	check := doctorCheck{Name: "data plane", Status: "pass", Details: access.Endpoint}
	if err != nil {
		report.OK = false
		check.Status = "fail"
		check.Details = doctorErrorDetails(err)
		if clierror.ExitCode(NormalizeError(err)) == clierror.ExitAuth && access.Mode == "api_key" {
			check.Details += "; check SCOPEDB_ENDPOINT and SCOPEDB_API_KEY belong to the same workspace and the key has not expired or been revoked"
		}
	}
	report.Checks = append(report.Checks, check)
}

func doctorErrorDetails(err error) string {
	normalized := NormalizeError(err)
	details := normalized.Error()
	var cliErr *clierror.Error
	if errors.As(normalized, &cliErr) {
		if cliErr.RequestID != "" {
			details += "; request ID: " + cliErr.RequestID
		}
		if cliErr.Hint != "" {
			details += "; " + cliErr.Hint
		}
	}
	return details
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
