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
	"slices"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/filelock"
	"github.com/scopedb/scopedb-cli/internal/output"
	"github.com/spf13/cobra"
)

type connectionListItem struct {
	Name      string `json:"name"`
	Default   bool   `json:"default"`
	Effective bool   `json:"effective"`
	config.Connection
}

func (a *app) newConnectionCommand() *cobra.Command {
	command := &cobra.Command{Use: "connection", Short: "Inspect saved connections or change the default", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	var format string
	list := &cobra.Command{Use: "list", Short: "List saved connections and last known identities", Args: cobra.NoArgs,
		Long: "List saved connections. Identity and workspace names are last known information; use 'scope --connection NAME auth status' to verify a login.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			_, cfg, err := a.connectionCatalog(cmd)
			if err != nil {
				return err
			}
			names := connectionNames(cfg)
			items := make([]connectionListItem, 0, len(names))
			for _, name := range names {
				items = append(items, connectionListItem{Name: name, Default: name == cfg.DefaultConnection, Effective: name == cfg.ConnectionName, Connection: cfg.Connections[name]})
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, items)
			}
			t := output.NewTable("DEFAULT", "EFFECTIVE", "CONNECTION", "AUTH TYPE", "LAST KNOWN EMAIL", "WORKSPACE ID", "ENDPOINT / CONTROL URL")
			for _, item := range items {
				current, effective := "", ""
				if item.Default {
					current = "*"
				}
				if item.Effective {
					effective = "*"
				}
				t.AppendRow(table.Row{current, effective, item.Name, item.AuthType, emptyDash(item.Email), emptyDash(item.WorkspaceID), item.CredentialOrigin()})
			}
			return output.WriteTable(a.out, t)
		},
	}
	list.Flags().StringVar(&format, "format", structuredFormatTable, "output format: table or json")
	var useFormat string
	use := &cobra.Command{Use: "set-default <name>", Short: "Change the saved default connection without logging in", Args: exactArgs(1), ValidArgsFunction: a.completeConnections,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTextFormat(useFormat); err != nil {
				return err
			}
			paths, _, err := a.connectionCatalog(cmd)
			if err != nil {
				return err
			}
			lock, err := filelock.Acquire(cmd.Context(), paths.LockFile)
			if err != nil {
				return err
			}
			defer func() { _ = lock.Close() }()
			cfg, err := config.Read(paths)
			if err != nil {
				return err
			}
			if _, ok := cfg.Connections[args[0]]; !ok {
				return fmt.Errorf("%w: %q", config.ErrUnknownConnection, args[0])
			}
			changed := cfg.DefaultConnection != args[0]
			cfg.DefaultConnection = args[0]
			if err := config.Save(paths, cfg); err != nil {
				return err
			}
			if err := a.warnMachineOverride(); err != nil {
				return err
			}
			if cmd.Root().PersistentFlags().Changed("connection") || strings.TrimSpace(a.getenv("SCOPEDB_CONNECTION")) != "" {
				if _, err := fmt.Fprintln(a.errOut, "An explicit --connection or SCOPEDB_CONNECTION still overrides the saved default."); err != nil {
					return err
				}
			}
			if useFormat == structuredFormatJSON {
				return writeJSON(a.out, connectionUseResult{Name: args[0], Changed: changed})
			}
			_, err = fmt.Fprintf(a.out, "Now using connection %s.\n", args[0])
			return err
		},
	}
	use.Flags().StringVar(&useFormat, "format", structuredFormatText, "output format: text or json")
	command.AddCommand(list, use, a.newConnectionAddCommand(), a.newConnectionRemoveCommand())
	return command
}

type connectionUseResult struct {
	Name    string `json:"name"`
	Changed bool   `json:"changed"`
}

func connectionNames(cfg config.Config) []string {
	names := make([]string, 0, len(cfg.Connections))
	for name := range cfg.Connections {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func (a *app) completeConnections(_ *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
	paths, err := config.ResolvePaths()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	cfg, err := config.Read(paths)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	var names []string
	for _, name := range connectionNames(cfg) {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

func (a *app) warnMachineOverride() error {
	if a.explicitConnection {
		return nil
	}
	endpoint := strings.TrimSpace(a.getenv("SCOPEDB_ENDPOINT"))
	key := strings.TrimSpace(a.getenv("SCOPEDB_API_KEY"))
	if endpoint == "" && key == "" {
		return nil
	}
	message := "Warning: data commands still use SCOPEDB_ENDPOINT and SCOPEDB_API_KEY from the environment; unset both to use your login workspace."
	if endpoint == "" || key == "" {
		message = "Warning: data commands require both SCOPEDB_ENDPOINT and SCOPEDB_API_KEY; set both or unset both to use your login workspace."
	}
	_, err := fmt.Fprintln(a.errOut, message)
	return err
}
