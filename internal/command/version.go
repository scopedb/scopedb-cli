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

	"github.com/scopedb/scopedb-cli/internal/version"
	"github.com/spf13/cobra"
)

func newVersionCommand(out io.Writer) *cobra.Command {
	var asJSON bool
	var format string
	command := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateTextFormat(format); err != nil {
				return err
			}
			if asJSON && cmd.Flags().Changed("format") && format != structuredFormatJSON {
				return usageError("--json and --format specify different formats")
			}
			info := version.Current()
			if asJSON || format == structuredFormatJSON {
				return writeJSON(out, info)
			}
			_, err := fmt.Fprintf(out, "scope %s (commit %s, built %s)\n", info.Version, info.Commit, info.Date)
			return err
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "print machine-readable JSON")
	command.Flags().StringVarP(&format, "format", "f", structuredFormatText, "output format: text or json")
	return command
}
