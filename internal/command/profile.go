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

type profileListItem struct {
	Name      string `json:"name"`
	Current   bool   `json:"current"`
	Effective bool   `json:"effective"`
	config.Profile
}

func (a *app) newProfileCommand() *cobra.Command {
	command := &cobra.Command{Use: "profile", Short: "Inspect saved profiles or change the default", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	var format string
	list := &cobra.Command{Use: "list", Short: "List saved profiles and last known identities", Args: cobra.NoArgs,
		Long: "List saved profiles. Identity and workspace names are last known information; use 'scope --profile NAME auth status' to verify a login.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			_, cfg, err := a.loadConfig(cmd)
			if err != nil {
				return err
			}
			names := profileNames(cfg)
			items := make([]profileListItem, 0, len(names))
			for _, name := range names {
				items = append(items, profileListItem{Name: name, Current: name == cfg.CurrentProfile, Effective: name == cfg.ProfileName, Profile: cfg.Profiles[name]})
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, items)
			}
			t := output.NewTable("CURRENT", "EFFECTIVE", "PROFILE", "LAST KNOWN EMAIL", "WORKSPACE ID", "CONTROL URL")
			for _, item := range items {
				current, effective := "", ""
				if item.Current {
					current = "*"
				}
				if item.Effective {
					effective = "*"
				}
				t.AppendRow(table.Row{current, effective, item.Name, emptyDash(item.Email), emptyDash(item.WorkspaceID), item.ControlURL})
			}
			return output.WriteTable(a.out, t)
		},
	}
	list.Flags().StringVar(&format, "format", structuredFormatTable, "output format: table or json")
	var useFormat string
	use := &cobra.Command{Use: "use <name>", Short: "Change the saved default profile without logging in", Args: exactArgs(1), ValidArgsFunction: a.completeProfiles,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTextFormat(useFormat); err != nil {
				return err
			}
			paths, _, err := a.loadConfig(cmd)
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
			if _, ok := cfg.Profiles[args[0]]; !ok {
				return fmt.Errorf("%w: %q", config.ErrUnknownProfile, args[0])
			}
			changed := cfg.CurrentProfile != args[0]
			cfg.CurrentProfile = args[0]
			if err := config.Save(paths, cfg); err != nil {
				return err
			}
			if err := a.warnMachineOverride(); err != nil {
				return err
			}
			if cmd.Root().PersistentFlags().Changed("profile") || strings.TrimSpace(a.getenv("SCOPEDB_PROFILE")) != "" {
				if _, err := fmt.Fprintln(a.errOut, "An explicit --profile or SCOPEDB_PROFILE still overrides the saved default."); err != nil {
					return err
				}
			}
			if useFormat == structuredFormatJSON {
				return writeJSON(a.out, profileUseResult{Name: args[0], Changed: changed})
			}
			_, err = fmt.Fprintf(a.out, "Now using profile %s.\n", args[0])
			return err
		},
	}
	use.Flags().StringVar(&useFormat, "format", structuredFormatText, "output format: text or json")
	command.AddCommand(list, use)
	return command
}

type profileUseResult struct {
	Name    string `json:"name"`
	Changed bool   `json:"changed"`
}

func profileNames(cfg config.Config) []string {
	names := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func (a *app) completeProfiles(_ *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
	paths, err := config.ResolvePaths()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	cfg, err := config.Read(paths)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	var names []string
	for _, name := range profileNames(cfg) {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

func (a *app) warnMachineOverride() error {
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
