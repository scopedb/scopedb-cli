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
	"strings"

	"github.com/spf13/cobra"
)

func (a *app) newOpenCommand() *cobra.Command {
	var printOnly bool
	command := &cobra.Command{
		Use:       "open [home|query|data|keys|connect]",
		Short:     "Open the ScopeDB console",
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{"home", "query", "data", "keys", "connect"},
		RunE: func(command *cobra.Command, args []string) error {
			page := "home"
			if len(args) == 1 {
				page = args[0]
			}
			switch page {
			case "home", "query", "data", "keys", "connect":
			default:
				return usageError(fmt.Sprintf("unsupported console page %q", page))
			}
			_, cfg, err := a.loadConfig(command)
			if err != nil {
				return NormalizeError(err)
			}
			target := strings.TrimRight(cfg.ConsoleURL, "/") + "/" + page
			if printOnly {
				fmt.Fprintln(a.out, target)
				return nil
			}
			if err := a.openURL(target); err != nil {
				return NormalizeError(err)
			}
			fmt.Fprintf(a.out, "Opened %s.\n", target)
			return nil
		},
	}
	command.Flags().BoolVar(&printOnly, "print", false, "print the URL without opening a browser")
	return command
}
