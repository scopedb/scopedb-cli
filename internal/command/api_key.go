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
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/output"
	"github.com/spf13/cobra"
)

func (a *app) newAPIKeyCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "api-key",
		Short: "Manage workspace API keys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
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
	var limit int
	command := &cobra.Command{
		Use:   "list",
		Short: "List API keys in the current workspace",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateStructuredFormat(format); err != nil {
				return err
			}
			if err := validateListLimit(limit); err != nil {
				return err
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return err
			}
			state, err := runtime.auth.LoadWorkspaceAccess(cmd.Context())
			if err != nil {
				return err
			}
			keys, err := runtime.control.ListAPIKeys(cmd.Context(), state.AccessToken, state.WorkspaceID)
			if err != nil {
				return err
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
			t := output.NewTable("NAME", "ID", "STATUS", "TAGS", "CREATED BY", "CREATED", "EXPIRES")
			for _, key := range keys {
				t.AppendRow(table.Row{
					key.Name,
					key.ID,
					key.Status,
					joinTags(key.Tags),
					key.CreatedBy,
					key.CreatedAt.UTC().Format(time.RFC3339),
					optionalTime(key.ExpiresAt),
				})
			}
			return output.WriteTable(a.out, t)
		},
	}
	command.Flags().StringVar(&format, "format", structuredFormatTable, "output format: table or json")
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

const defaultAPIKeyLifetime = 30 * 24 * time.Hour

func (a *app) newAPIKeyCreateCommand() *cobra.Command {
	var tags []string
	var expiresIn time.Duration
	var expiresAtValue string
	var format string
	command := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an API key in the current workspace",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "value" && format != structuredFormatJSON {
				return usageError(fmt.Sprintf("unsupported format %q; use value or json", format))
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
				return err
			}
			state, err := runtime.auth.LoadWorkspaceAccess(cmd.Context())
			if err != nil {
				return err
			}
			created, err := runtime.control.CreateAPIKey(cmd.Context(), state.AccessToken, state.WorkspaceID, controlplane.CreateAPIKeyRequest{
				Name:      name,
				Tags:      tags,
				ExpiresAt: expiresAt,
			})
			if err != nil {
				return err
			}
			if created.Key == "" {
				return fmt.Errorf("ScopeDB did not return the newly created API key")
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, created)
			}
			if _, err := fmt.Fprintln(a.out, created.Key); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(a.errOut, "Created API key %s, expiring %s. This secret is shown only once.\n", created.Name, expiresAt.Format(time.RFC3339)); err != nil {
				return err
			}
			return nil
		},
	}
	command.Flags().StringArrayVar(&tags, "tag", nil, "tag to attach; may be repeated")
	command.Flags().DurationVar(&expiresIn, "expires-in", 0, "relative expiration such as 720h or 12h; a default expiration applies unless --expires-in or --expires-at is set")
	command.Flags().StringVar(&expiresAtValue, "expires-at", "", "absolute RFC3339 expiration")
	command.Flags().StringVar(&format, "format", "value", "output format: value or json")
	return command
}

func (a *app) resolveAPIKeyExpiry(cmd *cobra.Command, expiresIn time.Duration, expiresAtValue string) (time.Time, error) {
	inChanged := cmd.Flags().Changed("expires-in")
	atChanged := cmd.Flags().Changed("expires-at")
	if inChanged && atChanged {
		return time.Time{}, usageError("--expires-in and --expires-at are mutually exclusive")
	}
	if inChanged {
		if expiresIn <= 0 {
			return time.Time{}, usageError("--expires-in must be positive")
		}
		return a.now().UTC().Add(expiresIn), nil
	}
	if atChanged {
		value, err := time.Parse(time.RFC3339, strings.TrimSpace(expiresAtValue))
		if err != nil {
			return time.Time{}, usageError("--expires-at must be an RFC3339 timestamp")
		}
		value = value.UTC()
		if !value.After(a.now().UTC()) {
			return time.Time{}, usageError("--expires-at must be in the future")
		}
		return value, nil
	}
	return a.now().UTC().Add(defaultAPIKeyLifetime), nil
}

func (a *app) newAPIKeyRevokeCommand() *cobra.Command {
	var yes bool
	var format string
	command := &cobra.Command{
		Use:   "revoke <id-or-name>",
		Short: "Revoke an API key by ID or unique name",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTextFormat(format); err != nil {
				return err
			}
			value := strings.TrimSpace(args[0])
			if value == "" {
				return usageError("API key ID or name must not be empty")
			}
			if !yes && !a.isInputTerminal() {
				return usageError("--yes is required when input is not interactive")
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return err
			}
			state, err := runtime.auth.LoadWorkspaceAccess(cmd.Context())
			if err != nil {
				return err
			}
			keys, err := runtime.control.ListAPIKeys(cmd.Context(), state.AccessToken, state.WorkspaceID)
			if err != nil {
				return err
			}
			key, err := resolveAPIKey(keys, value)
			if err != nil {
				return err
			}
			if !yes {
				answer, err := a.readLine(cmd.Context(), fmt.Sprintf("Revoke API key %s (%s)? [y/N] ", key.Name, key.ID))
				if err != nil {
					return err
				}
				if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
					if format == structuredFormatJSON {
						return writeJSON(a.out, apiKeyRevokeResult{ID: key.ID, Name: key.Name, Revoked: false})
					}
					_, err := fmt.Fprintln(a.out, "Cancelled.")
					return err
				}
				refreshed, err := runtime.auth.LoadAccess(cmd.Context())
				if err != nil {
					return err
				}
				// Waiting for confirmation may expire the token; keep the confirmed target.
				state.AccessToken = refreshed.AccessToken
			}
			if err := runtime.control.RevokeAPIKey(cmd.Context(), state.AccessToken, state.WorkspaceID, key.ID); err != nil {
				return err
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, apiKeyRevokeResult{ID: key.ID, Name: key.Name, Revoked: true})
			}
			_, err = fmt.Fprintf(a.out, "Revoked API key %s (%s).\n", key.Name, key.ID)
			return err
		},
	}
	command.Flags().BoolVarP(&yes, "yes", "y", false, "skip confirmation")
	command.Flags().StringVar(&format, "format", structuredFormatText, "output format: text or json")
	return command
}

func resolveAPIKey(keys []controlplane.APIKey, value string) (controlplane.APIKey, error) {
	for _, key := range keys {
		if key.ID == value {
			return key, nil
		}
	}
	var matches []controlplane.APIKey
	for _, key := range keys {
		if key.Name == value {
			matches = append(matches, key)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return controlplane.APIKey{}, clierror.WithHint(
			clierror.New(clierror.ExitNotFound, "API key was not found"),
			"use an ID from 'scope api-key list'",
		)
	default:
		return controlplane.APIKey{}, usageError("API key name is ambiguous; use its ID from 'scope api-key list'")
	}
}

type apiKeyRevokeResult struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Revoked bool   `json:"revoked"`
}
