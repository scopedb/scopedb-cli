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
	output           string
	force            bool
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
	for _, action := range []string{"get", "list", "plan", "apply", "drop"} {
		command.AddCommand(a.newCatalogActionCommand(action))
	}
	return command
}

func (a *app) newCatalogActionCommand(action string) *cobra.Command {
	var options catalogOptions
	description := map[string]string{
		"get":   "Export a resource definition",
		"list":  "List fully qualified resource names",
		"plan":  "Review changes without writing; optionally save a plan",
		"apply": "Review and apply a definition or saved plan",
		"drop":  "Delete an object or clear the tenant",
	}[action]
	command := &cobra.Command{
		Use: action, Short: description, Args: exactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return NormalizeError(a.runCatalog(cmd, action, args, options))
		},
	}
	for _, kind := range []string{"database", "schema", "table", "view"} {
		command.Flags().String(kind, "", "select one "+kind+" by its fully qualified name (scope flags are mutually exclusive)")
	}
	if action == "list" {
		command.Use = "list <databases|schemas|tables|views>"
		command.Args = exactArgs(1)
	}
	if action == "drop" {
		command.Flags().BoolVar(&options.all, "all", false, "clear the tenant's complete user catalog")
	}
	defaultOutput := ""
	if action == "get" || action == "list" {
		defaultOutput = "-"
	}
	command.Flags().StringVarP(&options.output, "output", "o", defaultOutput, "write structured output to a file; use - for stdout")
	command.Flags().BoolVar(&options.force, "force", false, "overwrite an existing output file")
	command.Flags().StringVar(&options.format, "format", "yaml", "structured output format: yaml or json")
	command.Flags().DurationVar(&options.timeout, "timeout", 5*time.Minute, "request timeout; 0 disables the limit")
	if action == "apply" || action == "plan" {
		command.Flags().StringVarP(&options.file, "file", "f", "", "definition file; use - for stdin")
		if action == "apply" {
			command.Flags().StringVar(&options.plan, "plan", "", "apply a saved plan without another prompt; use - for stdin")
			command.MarkFlagsMutuallyExclusive("file", "plan")
		}
	}
	if action == "apply" || action == "drop" {
		command.Flags().BoolVar(&options.yes, "yes", false, "skip interactive confirmation")
		command.Flags().BoolVar(&options.allowDestructive, "allow-destructive", false, "allow changes that may permanently lose data")
	}
	return command
}

func (a *app) runCatalog(cmd *cobra.Command, action string, args []string, options catalogOptions) error {
	if options.format != "yaml" && options.format != "json" {
		return usageError("catalog format must be yaml or json")
	}
	if options.timeout < 0 {
		return usageError("--timeout must not be negative")
	}
	resource := catalogResource{Kind: "catalog"}
	for _, kind := range []string{"database", "schema", "table", "view"} {
		if !cmd.Flags().Changed(kind) {
			continue
		}
		if resource.Kind != "catalog" || options.all {
			return usageError("select only one catalog scope")
		}
		if options.plan != "" {
			return usageError("--plan already contains the resource; omit scope flags")
		}
		name, err := cmd.Flags().GetString(kind)
		if err != nil {
			return err
		}
		resource = catalogResource{Kind: kind, Name: name}
	}
	if action == "drop" && resource.Kind == "catalog" && !options.all {
		return usageError("select a resource to drop, or use --all to clear the tenant")
	}
	if action == "list" {
		if err := resource.validateList(args[0]); err != nil {
			return err
		}
	}
	if action != "get" && action != "list" {
		return a.changeCatalog(cmd, action, resource, options)
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
	if action == "list" {
		names, err := catalogNames(resource, args[0], snapshot.Definition)
		if err != nil {
			return err
		}
		return a.writeCatalogOutput(names, options)
	}
	return a.writeCatalogOutput(snapshot.Definition, options)
}

// Time spent reviewing a diff does not consume either request's timeout.
func (o catalogOptions) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if o.timeout == 0 {
		return context.WithCancel(ctx)
	}
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
