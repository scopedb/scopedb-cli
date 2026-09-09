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

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/spf13/cobra"
)

// NewRootCommand constructs the complete command tree without package globals.
func NewRootCommand(deps Dependencies) *cobra.Command {
	a := newApp(deps)
	root := &cobra.Command{
		Use:           "scope",
		Short:         "ScopeDB from the command line",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	root.SetIn(a.in)
	root.SetOut(a.out)
	root.SetErr(a.errOut)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return clierror.Wrap(clierror.ExitUsage, err.Error(), err)
	})
	root.PersistentFlags().StringVar(&a.controlURLFlag, "control-url", "", "ScopeDB control-plane URL")
	root.PersistentFlags().StringVar(&a.consoleURLFlag, "console-url", "", "ScopeDB console URL")

	root.AddCommand(
		a.newLoginCommand(),
		a.newLogoutCommand(),
		a.newStatusCommand(),
		a.newWorkspaceCommand(),
		a.newQueryCommand(),
		a.newAPIKeyCommand(),
		a.newDoctorCommand(),
		a.newOpenCommand(),
		newVersionCommand(a.out),
		newCompletionCommand(root),
	)
	return root
}

func usageError(message string) error {
	return clierror.New(clierror.ExitUsage, message)
}

func exactArgs(count int) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) != count {
			return usageError(fmt.Sprintf("expected %d argument(s), received %d", count, len(args)))
		}
		return nil
	}
}
