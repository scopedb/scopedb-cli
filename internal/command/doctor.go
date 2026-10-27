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
	"github.com/scopedb/scopedb-cli/internal/output"
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
			"Uses your CLI login and its selected workspace.\n" +
			"Incomplete account setup is reported as a warning without running a query.\n" +
			"--timeout 0 disables the per-check limit; individual control-plane requests still have a 15s limit.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			if timeout < 0 {
				return usageError("--timeout must not be negative")
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return err
			}
			report := doctorReport{OK: true, Checks: []doctorCheck{
				{Name: "configuration", Status: "pass", Details: runtime.paths.Config},
			}}

			healthCtx, cancel := timeoutContext(cmd.Context(), timeout)
			healthErr := runtime.control.Health(healthCtx)
			cancel()
			if healthErr != nil {
				report.OK = false
				report.Checks = append(report.Checks, doctorCheck{Name: "control plane", Status: "fail", Details: clierror.Compact(NormalizeError(healthErr))})
			} else {
				report.Checks = append(report.Checks, doctorCheck{Name: "control plane", Status: "pass", Details: runtime.config.ControlURL})
			}

			state, loadErr := runtime.credentials.Load(runtime.config.ControlURL)
			if errors.Is(loadErr, credential.ErrNotFound) || errors.Is(loadErr, credential.ErrInvalidState) {
				report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "warn", Details: "not logged in; run 'scope auth login'"})
			} else if loadErr != nil {
				report.OK = false
				report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "fail", Details: clierror.Compact(NormalizeError(loadErr))})
			} else {
				source := state.Source
				if source == credential.SourcePlaintext {
					source += " (" + runtime.paths.CredentialsFile + ")"
				}
				report.Checks = append(report.Checks, doctorCheck{Name: "credential store", Status: "pass", Details: source})
				accountCtx, accountCancel := timeoutContext(cmd.Context(), timeout)
				account, _, accountErr := runtime.auth.Account(accountCtx)
				accountCancel()
				if accountErr != nil {
					report.OK = false
					report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "fail", Details: clierror.Compact(NormalizeError(accountErr))})
				} else {
					report.Checks = append(report.Checks, doctorCheck{Name: "authentication", Status: "pass", Details: account.User.Email})
					if setupErr := workspaceSetupError(auth.RequireWorkspace(account)); setupErr != nil {
						report.Checks = append(report.Checks, doctorCheck{Name: "workspace", Status: "warn", Details: fmt.Sprintf("%s; %s", setupErr.Message, setupErr.Hint)})
					} else {
						report.Checks = append(report.Checks, doctorCheck{Name: "workspace", Status: "pass", Details: account.SelectedWorkspaceID})
						a.checkDoctorDataPlane(cmd.Context(), runtime, timeout, &report)
					}
				}
			}

			if err := cmd.Context().Err(); err != nil {
				return err
			}
			if err := renderDoctor(a.out, format, report); err != nil {
				return err
			}
			if !report.OK {
				return clierror.New(clierror.ExitGeneral, "one or more checks failed")
			}
			return nil
		},
	}
	command.Flags().StringVar(&format, "format", structuredFormatTable, "output format: table or json")
	command.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "maximum time for each remote check, including query credential resolution; 0 disables the check limit")
	return command
}

func (a *app) checkDoctorDataPlane(ctx context.Context, runtime *runtimeContext, timeout time.Duration, report *doctorReport) {
	ctx, cancel := timeoutContext(ctx, timeout)
	defer cancel()
	access, err := runtime.auth.ResolveDataAccess(ctx)
	if err == nil {
		_, err = a.query.Execute(ctx, access, doctorStatement)
	}
	check := doctorCheck{Name: "data plane", Status: "pass", Details: access.Endpoint}
	if err != nil {
		report.OK = false
		check.Status = "fail"
		err = NormalizeError(err)
		check.Details = clierror.Compact(err)
	}
	report.Checks = append(report.Checks, check)
}

func renderDoctor(out io.Writer, format string, report doctorReport) error {
	if format == structuredFormatJSON {
		return writeJSON(out, report)
	}
	t := output.NewTable("CHECK", "STATUS", "DETAILS")
	for _, check := range report.Checks {
		t.AppendRow(table.Row{check.Name, check.Status, check.Details})
	}
	return output.WriteTable(out, t)
}
