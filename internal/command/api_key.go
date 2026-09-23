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
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/spf13/cobra"
)

func (a *app) newAPIKeyCommand() *cobra.Command {
	var workspace string
	command := &cobra.Command{
		Use:   "api-key",
		Short: "Manage workspace API keys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	command.PersistentFlags().StringVar(&workspace, "workspace", "", "use a workspace for this command without changing the default")
	command.AddCommand(
		a.newAPIKeyListCommand(&workspace),
		a.newAPIKeyCreateCommand(&workspace),
		a.newAPIKeyRevokeCommand(&workspace),
	)
	return command
}

func (a *app) newAPIKeyListCommand(workspace *string) *cobra.Command {
	var format string
	var limit int
	command := &cobra.Command{
		Use:   "list",
		Short: "List API keys in a workspace",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			if err := validateListLimit(limit); err != nil {
				return err
			}
			requested, err := requestedWorkspace(cmd, *workspace)
			if err != nil {
				return err
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			state, err := a.loadWorkspaceSession(cmd, runtime, requested)
			if err != nil {
				return NormalizeError(err)
			}
			keys, err := runtime.control.ListAPIKeys(cmd.Context(), state.SessionToken, state.WorkspaceID)
			if err != nil {
				return NormalizeError(err)
			}
			keys = limitedResults(keys, limit)
			if format == structuredFormatJSON {
				items := make([]apiKeyListItem, 0, len(keys))
				for _, key := range keys {
					items = append(items, apiKeyListItem{
						ID: key.ID, Name: key.Name, Tags: key.Tags, Status: key.Status,
						CreatedBy: key.CreatedBy, CreatedAt: key.CreatedAt,
						RevokedAt: key.RevokedAt, ExpiresAt: key.ExpiresAt,
					})
				}
				return writeJSON(a.out, items)
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
	command.Flags().IntVarP(&limit, "limit", "L", 0, "maximum results to display (0 means all)")
	return command
}

// apiKeyListItem intentionally excludes the one-time secret returned by create.
type apiKeyListItem struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Tags      []string   `json:"tags"`
	Status    string     `json:"status"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (a *app) newAPIKeyCreateCommand(workspace *string) *cobra.Command {
	var tags []string
	var expiresIn time.Duration
	var expiresAtValue string
	var format string
	command := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an API key in a workspace",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "value" && format != structuredFormatJSON {
				return usageError(fmt.Sprintf("unsupported format %q; use value or json", format))
			}
			requested, err := requestedWorkspace(cmd, *workspace)
			if err != nil {
				return err
			}
			name := strings.TrimSpace(args[0])
			if name == "" {
				return usageError("API key name must not be empty")
			}
			expiresAt, err := a.resolveAPIKeyExpiry(cmd, expiresIn, expiresAtValue)
			if err != nil {
				return err
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			state, err := a.loadWorkspaceSession(cmd, runtime, requested)
			if err != nil {
				return NormalizeError(err)
			}
			created, err := runtime.control.CreateAPIKey(cmd.Context(), state.SessionToken, state.WorkspaceID, controlplane.CreateAPIKeyRequest{
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

func (a *app) resolveAPIKeyExpiry(cmd *cobra.Command, expiresIn time.Duration, expiresAtValue string) (*time.Time, error) {
	inChanged := cmd.Flags().Changed("expires-in")
	atChanged := cmd.Flags().Changed("expires-at")
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

func (a *app) newAPIKeyRevokeCommand(workspace *string) *cobra.Command {
	var yes bool
	var format string
	command := &cobra.Command{
		Use:   "revoke <name>",
		Short: "Revoke an API key",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTextFormat(format); err != nil {
				return err
			}
			requested, err := requestedWorkspace(cmd, *workspace)
			if err != nil {
				return err
			}
			name := strings.TrimSpace(args[0])
			if name == "" {
				return usageError("API key name must not be empty")
			}
			if !yes {
				if a.promptsDisabled(cmd) {
					return usageError("--yes is required when prompts are disabled")
				}
				if !a.isInputTerminal() {
					return usageError("--yes is required when input is not interactive")
				}
				prompt := fmt.Sprintf("Revoke API key %s", name)
				if requested != "" {
					prompt += " in workspace " + requested
				}
				answer, err := a.readLine(cmd.Context(), prompt+"? [y/N] ")
				if err != nil {
					return NormalizeError(err)
				}
				if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
					if format == structuredFormatJSON {
						return writeJSON(a.out, apiKeyRevokeResult{Name: name, Revoked: false})
					}
					_, err := fmt.Fprintln(a.out, "Cancelled.")
					return NormalizeError(err)
				}
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			state, err := a.loadWorkspaceSession(cmd, runtime, requested)
			if err != nil {
				return NormalizeError(err)
			}
			if err := runtime.control.RevokeAPIKey(cmd.Context(), state.SessionToken, state.WorkspaceID, name); err != nil {
				return NormalizeError(err)
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, apiKeyRevokeResult{Name: name, Revoked: true})
			}
			_, err = fmt.Fprintf(a.out, "Revoked API key %s.\n", name)
			return NormalizeError(err)
		},
	}
	command.Flags().BoolVarP(&yes, "yes", "y", false, "skip confirmation")
	command.Flags().StringVarP(&format, "format", "f", structuredFormatText, "output format: text or json")
	return command
}

type apiKeyRevokeResult struct {
	Name    string `json:"name"`
	Revoked bool   `json:"revoked"`
}
