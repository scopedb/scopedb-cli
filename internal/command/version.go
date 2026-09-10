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
	"encoding/json"
	"fmt"
	"io"

	"github.com/scopedb/scopedb-cli/internal/version"
	"github.com/spf13/cobra"
)

func newVersionCommand(out io.Writer) *cobra.Command {
	var asJSON bool
	command := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			info := version.Current()
			if asJSON {
				encoder := json.NewEncoder(out)
				encoder.SetIndent("", "  ")
				return encoder.Encode(info)
			}
			_, err := fmt.Fprintf(out, "scope %s (commit %s, built %s)\n", info.Version, info.Commit, info.Date)
			return err
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "print machine-readable JSON")
	return command
}
