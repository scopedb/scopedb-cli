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

	"github.com/spf13/cobra"
)

func (a *app) newConsoleCommand() *cobra.Command {
	var openBrowser bool
	var format string
	command := &cobra.Command{
		Use:   "console",
		Short: "Print the ScopeDB console URL, optionally opening it in a browser",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTextFormat(format); err != nil {
				return err
			}
			_, cfg, err := a.loadConfig(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			if openBrowser {
				if err := a.openURL(cfg.ConsoleURL); err != nil {
					return NormalizeError(err)
				}
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, consoleResult{URL: cfg.ConsoleURL, Opened: openBrowser})
			}
			_, err = fmt.Fprintln(a.out, cfg.ConsoleURL)
			return NormalizeError(err)
		},
	}
	command.Flags().BoolVar(&openBrowser, "open", false, "open the URL in the default browser")
	command.Flags().StringVarP(&format, "format", "f", structuredFormatText, "output format: text or json")
	return command
}

type consoleResult struct {
	URL    string `json:"url"`
	Opened bool   `json:"opened"`
}
