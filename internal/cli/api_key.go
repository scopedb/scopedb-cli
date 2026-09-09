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
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/spf13/cobra"
)

func (a *app) newAPIKeyCommand() *cobra.Command {
	command := &cobra.Command{
		Use:     "api-key",
		Aliases: []string{"api-keys"},
		Short:   "Manage workspace API keys",
		Args:    cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	command.AddCommand(
		a.newAPIKeyListCommand(),
		a.newAPIKeyCreateCommand(),
		a.newAPIKeyRevokeCommand(),
	)
	return command
}

func (a *app) newAPIKeyListCommand() *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "list",
		Short: "List API keys in the current workspace",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			runtime, err := a.runtime(command)
			if err != nil {
				return NormalizeError(err)
			}
			state, _, err := runtime.auth.LoadSession(command.Context())
			if err != nil {
				return NormalizeError(err)
			}
			keys, err := runtime.control.ListAPIKeys(command.Context(), state.SessionToken, state.WorkspaceID)
			if err != nil {
				return NormalizeError(err)
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, keys)
			}
			t := newTable(a.out, "NAME", "ID", "STATUS", "TAGS", "CREATED", "EXPIRES")
			for _, key := range keys {
				t.AppendRow(table.Row{
					key.Name,
					key.ID,
					key.Status,
					joinTags(key.Tags),
					key.CreatedAt.UTC().Format(time.RFC3339),
					optionalTime(key.ExpiresAt),
				})
			}
			t.Render()
			return nil
		},
	}
	command.Flags().StringVarP(&format, "format", "f", structuredFormatTable, "output format: table or json")
	return command
}

func (a *app) newAPIKeyCreateCommand() *cobra.Command {
	var tags []string
	var expiresIn time.Duration
	var expiresAtValue string
	var format string
	command := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an API key in the current workspace",
		Args:  exactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			if format != "value" && format != structuredFormatJSON {
				return usageError(fmt.Sprintf("unsupported format %q; use value or json", format))
			}
			name := strings.TrimSpace(args[0])
			if name == "" {
				return usageError("API key name must not be empty")
			}
			expiresAt, err := a.resolveAPIKeyExpiry(command, expiresIn, expiresAtValue)
			if err != nil {
				return err
			}
			runtime, err := a.runtime(command)
			if err != nil {
				return NormalizeError(err)
			}
			state, _, err := runtime.auth.LoadSession(command.Context())
			if err != nil {
				return NormalizeError(err)
			}
			created, err := runtime.control.CreateAPIKey(command.Context(), state.SessionToken, state.WorkspaceID, controlplane.CreateAPIKeyRequest{
				Name:      name,
				Tags:      tags,
				ExpiresAt: expiresAt,
			})
			if err != nil {
				return NormalizeError(err)
			}
			if created.Key == "" {
				return NormalizeError(fmt.Errorf("ScopeDB did not return the newly created API key"))
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, created)
			}
			if _, err := fmt.Fprintln(a.out, created.Key); err != nil {
				return NormalizeError(err)
			}
			if _, err := fmt.Fprintf(a.errOut, "Created API key %s. This secret is shown only once.\n", created.Name); err != nil {
				return NormalizeError(err)
			}
			return nil
		},
	}
	command.Flags().StringArrayVar(&tags, "tag", nil, "tag to attach; may be repeated")
	command.Flags().DurationVar(&expiresIn, "expires-in", 0, "relative expiration such as 720h or 12h")
	command.Flags().StringVar(&expiresAtValue, "expires-at", "", "absolute RFC3339 expiration")
	command.Flags().StringVarP(&format, "format", "f", "value", "output format: value or json")
	return command
}

func (a *app) resolveAPIKeyExpiry(command *cobra.Command, expiresIn time.Duration, expiresAtValue string) (*time.Time, error) {
	inChanged := command.Flags().Changed("expires-in")
	atChanged := command.Flags().Changed("expires-at")
	if inChanged && atChanged {
		return nil, usageError("--expires-in and --expires-at are mutually exclusive")
	}
	if inChanged {
		if expiresIn <= 0 {
			return nil, usageError("--expires-in must be positive")
		}
		value := a.now().UTC().Add(expiresIn)
		return &value, nil
	}
	if atChanged {
		value, err := time.Parse(time.RFC3339, strings.TrimSpace(expiresAtValue))
		if err != nil {
			return nil, usageError("--expires-at must be an RFC3339 timestamp")
		}
		value = value.UTC()
		if !value.After(a.now().UTC()) {
			return nil, usageError("--expires-at must be in the future")
		}
		return &value, nil
	}
	return nil, nil
}

func (a *app) newAPIKeyRevokeCommand() *cobra.Command {
	var yes bool
	command := &cobra.Command{
		Use:   "revoke <name>",
		Short: "Revoke an API key",
		Args:  exactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			if name == "" {
				return usageError("API key name must not be empty")
			}
			if !yes {
				if !a.isInputTerminal() {
					return usageError("--yes is required when input is not interactive")
				}
				answer, err := a.readLine(fmt.Sprintf("Revoke API key %s? [y/N] ", name))
				if err != nil {
					return NormalizeError(err)
				}
				if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
					_, err := fmt.Fprintln(a.out, "Cancelled.")
					return NormalizeError(err)
				}
			}
			runtime, err := a.runtime(command)
			if err != nil {
				return NormalizeError(err)
			}
			state, _, err := runtime.auth.LoadSession(command.Context())
			if err != nil {
				return NormalizeError(err)
			}
			if err := runtime.control.RevokeAPIKey(command.Context(), state.SessionToken, state.WorkspaceID, name); err != nil {
				return NormalizeError(err)
			}
			_, err = fmt.Fprintf(a.out, "Revoked API key %s.\n", name)
			return NormalizeError(err)
		},
	}
	command.Flags().BoolVarP(&yes, "yes", "y", false, "skip confirmation")
	return command
}
