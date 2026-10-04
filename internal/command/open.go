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
	"strings"

	"github.com/spf13/cobra"
)

func (a *app) newOpenCommand() *cobra.Command {
	var printOnly bool
	var format string
	command := &cobra.Command{
		Use:       "open [home|query|data|keys|connect]",
		Short:     "Open the ScopeDB console",
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{"home", "query", "data", "keys", "connect"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTextFormat(format); err != nil {
				return err
			}
			page := "home"
			if len(args) == 1 {
				page = args[0]
			}
			switch page {
			case "home", "query", "data", "keys", "connect":
			default:
				return usageError(fmt.Sprintf("unsupported console page %q", page))
			}
			_, cfg, err := a.loadConfig(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			target := strings.TrimRight(cfg.ConsoleURL, "/") + "/" + page
			if printOnly {
				if format == structuredFormatJSON {
					return writeJSON(a.out, openResult{Page: page, URL: target, Opened: false})
				}
				_, err := fmt.Fprintln(a.out, target)
				return NormalizeError(err)
			}
			if err := a.openURL(target); err != nil {
				return NormalizeError(err)
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, openResult{Page: page, URL: target, Opened: true})
			}
			_, err = fmt.Fprintf(a.out, "Opened %s.\n", target)
			return NormalizeError(err)
		},
	}
	command.Flags().BoolVar(&printOnly, "print", false, "print the URL without opening a browser")
	command.Flags().StringVarP(&format, "format", "f", structuredFormatText, "output format: text or json")
	return command
}

type openResult struct {
	Page   string `json:"page"`
	URL    string `json:"url"`
	Opened bool   `json:"opened"`
}
