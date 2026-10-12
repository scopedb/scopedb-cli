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
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/dataplane"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type catalogPlan struct {
	Version        int             `json:"version"`
	Endpoint       string          `json:"endpoint"`
	WorkspaceID    string          `json:"workspace_id,omitempty"`
	CredentialHash string          `json:"credential_hash,omitempty"`
	Resource       catalogResource `json:"resource"`
	Method         string          `json:"method"`
	Definition     json.RawMessage `json:"definition,omitempty"`
	ETag           string          `json:"etag"`
	dataplane.CatalogChange
}

type catalogOptions struct {
	file    string
	plan    string
	format  string
	drop    bool
	yes     bool
	timeout time.Duration
}

func (a *app) newCatalogCommand() *cobra.Command {
	command := &cobra.Command{
		Use: "catalog", Short: "Get, plan, apply, or drop catalog definitions",
		Long: "Manage complete catalog resources. Omitted objects and fields are cleared.\n\nResources: databases, database DB, schemas DB, schema DB.SCHEMA,\n           tables DB.SCHEMA, table DB.SCHEMA.TABLE,\n           views DB.SCHEMA, view DB.SCHEMA.VIEW.\nUse backticks for names containing dots or special characters.\nDefinitions and plans use YAML (or JSON with --format json).",
	}
	for _, action := range []string{"get", "plan", "apply", "drop"} {
		options := catalogOptions{}
		description := map[string]string{
			"get":   "Export a resource definition",
			"plan":  "Validate and save a change without writing",
			"apply": "Review and apply a definition or saved plan",
			"drop":  "Delete an object or clear a collection",
		}[action]
		child := &cobra.Command{
			Use: action + " <resource> [qualified-name]", Short: description,
			RunE: func(cmd *cobra.Command, args []string) error {
				return NormalizeError(a.runCatalog(cmd, action, args, options))
			},
		}
		child.Flags().StringVar(&options.format, "format", "yaml", "output format: yaml or json")
		child.Flags().DurationVar(&options.timeout, "timeout", 5*time.Minute, "request timeout; 0 disables the limit")
		if action == "plan" || action == "apply" {
			child.Flags().StringVarP(&options.file, "file", "f", "", "definition file; use - for stdin")
		}
		if action == "plan" {
			child.Flags().BoolVar(&options.drop, "drop", false, "plan deletion of the resource")
			child.MarkFlagsMutuallyExclusive("file", "drop")
		}
		if action == "apply" {
			child.Use = "apply [<resource> [qualified-name]]"
			child.Flags().StringVar(&options.plan, "plan", "", "apply a saved plan without another prompt; use - for stdin")
			child.MarkFlagsMutuallyExclusive("file", "plan")
		}
		if action == "apply" || action == "drop" {
			child.Flags().BoolVar(&options.yes, "yes", false, "approve all changes, including deletions")
		}
		command.AddCommand(child)
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
	var plan catalogPlan
	if options.plan != "" {
		if len(args) != 0 {
			return usageError("--plan already contains the resource; omit positional arguments")
		}
		data, err := a.readCatalog(options.plan)
		if err != nil {
			return err
		}
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&plan); err != nil {
			return usageError("invalid catalog plan: " + err.Error())
		}
		if plan.Version != 1 || plan.Endpoint == "" || plan.ETag == "" || len(plan.Before) == 0 || len(plan.After) == 0 {
			return usageError("invalid catalog plan; generate it with 'scope catalog plan'")
		}
		if plan.Method != http.MethodPut && plan.Method != http.MethodDelete {
			return usageError("catalog plan method must be PUT or DELETE")
		}
	} else {
		if len(args) < 1 || len(args) > 2 {
			return usageError("provide a resource kind and its fully qualified name")
		}
		plan.Resource.Kind = args[0]
		if len(args) == 2 {
			plan.Resource.Name = args[1]
		}
		if action == "drop" || options.drop {
			plan.Method, plan.Definition = plan.Resource.drop()
		} else if action != "get" {
			if options.file == "" {
				return usageError("provide --file (-f), or use --file - for stdin")
			}
			definition, err := a.readCatalog(options.file)
			if err != nil {
				return err
			}
			plan.Method, plan.Definition = http.MethodPut, definition
		}
	}
	segments, err := plan.Resource.segments()
	if err != nil {
		return err
	}
	if plan.Method == http.MethodPut && (len(plan.Definition) == 0 || plan.Definition[0] != '{') {
		return usageError("catalog definition must be an object; use drop to delete an object")
	}
	if plan.Method == http.MethodDelete {
		method, _ := plan.Resource.drop()
		if method != http.MethodDelete || len(plan.Definition) != 0 {
			return usageError("DELETE plans require a single object and no definition")
		}
	}
	rt, err := a.runtime(cmd)
	if err != nil {
		return err
	}
	access, err := rt.auth.ResolveDataAccess(cmd.Context())
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(access.Endpoint, "/")
	credentialHash := ""
	if access.WorkspaceID == "" {
		// Machine credentials carry no workspace ID, so pin the credential without storing it.
		credentialHash = fmt.Sprintf("%x", sha256.Sum256([]byte(access.APIKey)))
	}
	if options.plan != "" && (plan.Endpoint != endpoint || plan.WorkspaceID != access.WorkspaceID || plan.CredentialHash != credentialHash) {
		return usageError("plan targets a different connection, workspace, or machine credential; select its connection or generate a new plan")
	}
	service := dataplane.CatalogService{HTTPClient: a.httpClient}
	// Each request gets a fresh deadline; time spent reviewing the diff is unbounded.
	requestContext := func() (context.Context, context.CancelFunc) {
		if options.timeout == 0 {
			return context.WithCancel(cmd.Context())
		}
		return context.WithTimeout(cmd.Context(), options.timeout)
	}
	if action == "get" {
		ctx, cancel := requestContext()
		defer cancel()
		definition, err := service.Get(ctx, access, segments)
		if err != nil {
			return err
		}
		return writeCatalog(a.out, definition, options.format)
	}
	if options.plan == "" {
		ctx, cancel := requestContext()
		change, etag, err := service.Mutate(ctx, access, plan.Method, segments, plan.Definition, true, "")
		cancel()
		if err != nil {
			return err
		}
		plan.Version, plan.Endpoint, plan.WorkspaceID = 1, endpoint, access.WorkspaceID
		plan.CredentialHash = credentialHash
		plan.ETag, plan.CatalogChange = etag, change
	}
	if action == "plan" {
		return writeCatalog(a.out, plan, options.format)
	}
	diff, err := catalogDiff(plan.CatalogChange)
	if err != nil {
		return err
	}
	if diff != "" {
		if _, err := fmt.Fprint(a.errOut, diff); err != nil {
			return err
		}
		if !options.yes && options.plan == "" {
			if err := a.confirmCatalog(cmd.Context(), options.file == "-"); err != nil {
				return err
			}
		}
	} else if _, err := fmt.Fprintln(a.errOut, "No changes."); err != nil {
		return err
	}
	ctx, cancel := requestContext()
	defer cancel()
	result, _, err := service.Mutate(ctx, access, plan.Method, segments, plan.Definition, false, plan.ETag)
	if err != nil {
		return err
	}
	return writeCatalog(a.out, result, options.format)
}

func (a *app) confirmCatalog(ctx context.Context, stdinConsumed bool) error {
	reader := a.input
	if stdinConsumed || !a.isInputTerminal() {
		path := "/dev/tty"
		if runtime.GOOS == "windows" {
			path = "CONIN$"
		}
		terminal, err := os.Open(path)
		if err != nil {
			return usageError("confirmation requires a terminal; pass --yes or apply a saved plan")
		}
		defer func() { _ = terminal.Close() }()
		if !term.IsTerminal(int(terminal.Fd())) {
			return usageError("confirmation requires a terminal; pass --yes or apply a saved plan")
		}
		reader = bufio.NewReader(terminal)
	}
	if _, err := fmt.Fprint(a.errOut, "Press Enter to apply all changes, including deletions; Ctrl-C to cancel: "); err != nil {
		return err
	}
	type reply struct {
		text string
		err  error
	}
	done := make(chan reply, 1)
	go func() { text, err := reader.ReadString('\n'); done <- reply{text, err} }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case response := <-done:
		if response.err != nil || strings.TrimSpace(response.text) != "" {
			return clierror.New(clierror.ExitInterrupted, "catalog apply cancelled")
		}
		return nil
	}
}
