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
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	scopedb "github.com/scopedb/goscopedb"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/spf13/cobra"
)

type catalogOptions struct {
	file             string
	plan             string
	format           string
	all              bool
	yes              bool
	allowDestructive bool
	timeout          time.Duration
}

func (a *app) newCatalogCommand() *cobra.Command {
	command := &cobra.Command{
		Use: "catalog", Short: "List, get, plan, apply, or drop catalog resources",
		Long: "Manage complete catalog resources. Omitted objects and fields are cleared.\n\nGet, apply, and plan default to the entire tenant. Select one resource with\n--database DB, --schema DB.SCHEMA, --table DB.SCHEMA.TABLE, or --view DB.SCHEMA.VIEW.\nNames must be fully qualified; use backticks for dots or special characters.\nDefinitions and plans use YAML (or JSON with --format json).",
	}
	command.AddCommand(a.newCatalogGetCommand(), a.newCatalogListCommand(), a.newCatalogPlanCommand(), a.newCatalogApplyCommand(), a.newCatalogDropCommand())
	return command
}

func (o *catalogOptions) addFlags(command *cobra.Command) {
	for _, kind := range []string{"database", "schema", "table", "view"} {
		command.Flags().String(kind, "", "select one "+kind+" by its fully qualified name")
	}
	command.Flags().StringVar(&o.format, "format", "yaml", "output format: yaml or json")
	command.Flags().DurationVar(&o.timeout, "timeout", 5*time.Minute, "per-request timeout (must be positive)")
	command.PreRunE = func(_ *cobra.Command, _ []string) error {
		if o.format != "yaml" && o.format != "json" {
			return usageError("catalog format must be yaml or json")
		}
		if o.timeout <= 0 {
			return usageError("--timeout must be positive")
		}
		return nil
	}
}

func (o *catalogOptions) addConfirmationFlags(command *cobra.Command) {
	command.Flags().BoolVarP(&o.yes, "yes", "y", false, "skip interactive confirmation")
	command.Flags().BoolVar(&o.allowDestructive, "allow-destructive", false, "allow changes that may permanently lose data")
}

func (a *app) newCatalogGetCommand() *cobra.Command {
	var options catalogOptions
	command := &cobra.Command{
		Use: "get", Short: "Export a resource definition", Args: exactArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return NormalizeError(a.readCatalogResource(cmd, "", options))
		},
	}
	options.addFlags(command)
	return command
}

func (a *app) newCatalogListCommand() *cobra.Command {
	var options catalogOptions
	command := &cobra.Command{
		Use: "list <databases|schemas|tables|views>", Short: "List fully qualified resource names", Args: exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return NormalizeError(a.readCatalogResource(cmd, args[0], options))
		},
	}
	options.addFlags(command)
	return command
}

func (a *app) newCatalogPlanCommand() *cobra.Command {
	var options catalogOptions
	command := &cobra.Command{
		Use: "plan", Short: "Preview changes and write a reusable plan to stdout", Args: exactArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return NormalizeError(a.changeCatalog(cmd, "plan", options))
		},
	}
	options.addFlags(command)
	command.Flags().StringVarP(&options.file, "file", "f", "", "definition file; use - for stdin")
	return command
}

func (a *app) newCatalogApplyCommand() *cobra.Command {
	var options catalogOptions
	command := &cobra.Command{
		Use: "apply", Short: "Review and apply a definition or saved plan", Args: exactArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return NormalizeError(a.changeCatalog(cmd, "apply", options))
		},
	}
	options.addFlags(command)
	options.addConfirmationFlags(command)
	command.Flags().StringVarP(&options.file, "file", "f", "", "definition file; use - for stdin")
	command.Flags().StringVar(&options.plan, "plan", "", "apply a saved plan without another prompt; use - for stdin")
	command.MarkFlagsMutuallyExclusive("file", "plan")
	return command
}

func (a *app) newCatalogDropCommand() *cobra.Command {
	var options catalogOptions
	command := &cobra.Command{
		Use: "drop", Short: "Delete an object or clear the tenant", Args: exactArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return NormalizeError(a.changeCatalog(cmd, "drop", options))
		},
	}
	options.addFlags(command)
	options.addConfirmationFlags(command)
	command.Flags().BoolVar(&options.all, "all", false, "clear the tenant's complete user catalog")
	return command
}

func (o catalogOptions) resource(cmd *cobra.Command) (catalogResource, error) {
	resource := catalogResource{Kind: "catalog"}
	for _, kind := range []string{"database", "schema", "table", "view"} {
		if !cmd.Flags().Changed(kind) {
			continue
		}
		if resource.Kind != "catalog" || o.all {
			return resource, usageError("select only one catalog scope")
		}
		if o.plan != "" {
			return resource, usageError("--plan already contains the resource; omit scope flags")
		}
		name, err := cmd.Flags().GetString(kind)
		if err != nil {
			return resource, err
		}
		resource = catalogResource{Kind: kind, Name: name}
	}
	return resource, nil
}

func (a *app) readCatalogResource(cmd *cobra.Command, list string, options catalogOptions) error {
	resource, err := options.resource(cmd)
	if err != nil {
		return err
	}
	if list != "" {
		if err := resource.validateList(list); err != nil {
			return err
		}
	}
	names, err := resource.names()
	if err != nil {
		return err
	}
	rt, err := a.runtime(cmd)
	if err != nil {
		return err
	}
	access, err := rt.auth.ResolveDataAccess(cmd.Context())
	if err != nil {
		return err
	}
	client, err := scopedb.NewClient(scopedb.Config{Endpoint: access.Endpoint, APIKey: access.APIKey, HTTPClient: a.httpClient})
	if err != nil {
		return err
	}
	defer client.Close()
	catalog := resource.resolve(client, names)
	ctx, cancel := options.requestContext(cmd.Context())
	defer cancel()
	snapshot, err := catalog.Get(ctx)
	if err != nil {
		return err
	}
	if list != "" {
		names, err := catalogNames(resource, list, snapshot.Definition)
		if err != nil {
			return err
		}
		return writeCatalog(a.out, names, options.format)
	}
	return writeCatalog(a.out, snapshot.Definition, options.format)
}

// Time spent reviewing a diff does not consume either request's timeout.
func (o catalogOptions) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, o.timeout)
}

func normalizeCatalogError(catalogErr *scopedb.Error) error {
	code := clierror.ExitGeneral
	if errors.Is(catalogErr, context.DeadlineExceeded) || catalogErr.HTTPStatus == http.StatusRequestTimeout || catalogErr.HTTPStatus == http.StatusTooManyRequests || catalogErr.HTTPStatus >= 500 {
		code = clierror.ExitTemporary
	}
	hint := ""
	switch catalogErr.HTTPStatus {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		code = clierror.ExitUsage
	case http.StatusUnauthorized, http.StatusForbidden:
		code = clierror.ExitAuth
	case http.StatusNotFound:
		code = clierror.ExitNotFound
	case http.StatusPreconditionFailed:
		hint = "catalog changed; generate a new plan and review its diff"
	}
	if catalogErr.Code == "catalog_destructive_change" {
		code = clierror.ExitUsage
		hint = "review a new plan and pass --allow-destructive to permit data loss"
	}
	if catalogErr.Code == "catalog_commit_outcome_unknown" {
		code = clierror.ExitGeneral
		if errors.Is(catalogErr, context.DeadlineExceeded) {
			code = clierror.ExitTemporary
		}
		hint = "read the catalog and plan again before retrying"
	}
	if errors.Is(catalogErr, context.Canceled) {
		code = clierror.ExitInterrupted
		if catalogErr.Code != "catalog_commit_outcome_unknown" {
			hint = ""
		}
	}
	message := catalogErr.Message
	if catalogErr.Code != "" {
		message = catalogErr.Code + ": " + message
	}
	if catalogErr.HTTPStatus != 0 {
		message = fmt.Sprintf("HTTP %d: %s", catalogErr.HTTPStatus, message)
	}
	result := clierror.WithHint(clierror.Wrap(code, message, catalogErr), hint)
	result.RequestID = catalogErr.RequestID
	return result
}
