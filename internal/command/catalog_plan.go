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
	Definition     json.RawMessage `json:"definition"`
	ETag           string          `json:"etag"`
	dataplane.CatalogChange
}

func (a *app) changeCatalog(cmd *cobra.Command, action string, resource catalogResource, options catalogOptions) error {
	var plan catalogPlan
	var method string
	if options.plan != "" {
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
		method = http.MethodPut
	} else {
		plan.Resource = resource
		if action == "drop" {
			method = http.MethodDelete
			if options.all {
				method, plan.Definition = http.MethodPut, json.RawMessage(`{"databases":[]}`)
			}
		} else {
			if options.file == "" {
				return usageError("provide --file (-f), or use --file - for stdin")
			}
			definition, err := a.readCatalog(options.file)
			if err != nil {
				return err
			}
			method, plan.Definition = http.MethodPut, definition
		}
	}
	segments, err := plan.Resource.segments()
	if err != nil {
		return err
	}
	if method == http.MethodPut && (len(plan.Definition) == 0 || plan.Definition[0] != '{') {
		return usageError("catalog definition must be an object; use drop to delete an object")
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
	service := dataplane.CatalogService{HTTPClient: a.httpClient}
	if options.plan != "" {
		if plan.Endpoint != endpoint || plan.WorkspaceID != access.WorkspaceID || plan.CredentialHash != credentialHash {
			return usageError("plan targets a different connection, workspace, or machine credential; select its connection or generate a new plan")
		}
		if plan.Destructive && !options.allowDestructive {
			return usageError("changes may permanently lose data; review the plan and pass --allow-destructive")
		}
		ctx, cancel := options.requestContext(cmd.Context())
		defer cancel()
		result, _, err := service.Mutate(ctx, access, dataplane.CatalogRequest{
			Method: method, Resource: segments, Definition: plan.Definition,
			AllowDestructive: options.allowDestructive, ETag: plan.ETag,
		})
		if err != nil {
			return err
		}
		return writeCatalog(a.out, result, options.format)
	}
	ctx, cancel := options.requestContext(cmd.Context())
	change, etag, err := service.Mutate(ctx, access, dataplane.CatalogRequest{
		Method: method, Resource: segments, Definition: plan.Definition, DryRun: true,
	})
	cancel()
	if err != nil {
		return err
	}
	plan.Version, plan.Endpoint, plan.WorkspaceID = 1, endpoint, access.WorkspaceID
	plan.CredentialHash = credentialHash
	plan.ETag, plan.CatalogChange = etag, change
	diff, err := catalogDiff(plan.Resource, plan.CatalogChange)
	if err != nil {
		return err
	}
	if diff != "" {
		if _, err := fmt.Fprint(a.errOut, diff); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintln(a.errOut, "No changes."); err != nil {
		return err
	}
	if plan.Destructive {
		if _, err := fmt.Fprintln(a.errOut, "Warning: these changes may permanently lose data."); err != nil {
			return err
		}
	}
	if action == "plan" {
		return writeCatalog(a.out, plan, options.format)
	}
	if plan.Destructive && !options.allowDestructive && options.yes {
		return usageError("changes may permanently lose data; review the diff and pass --allow-destructive")
	}
	if (diff != "" || plan.Destructive) && !options.yes {
		if err := a.confirmCatalog(cmd.Context(), options.file == "-"); err != nil {
			return err
		}
		options.allowDestructive = options.allowDestructive || plan.Destructive
	}
	ctx, cancel = options.requestContext(cmd.Context())
	defer cancel()
	result, _, err := service.Mutate(ctx, access, dataplane.CatalogRequest{
		Method: method, Resource: segments, Definition: plan.Definition,
		AllowDestructive: options.allowDestructive, ETag: plan.ETag,
	})
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
	if _, err := fmt.Fprint(a.errOut, "Press Enter to apply these changes; Ctrl-C to cancel: "); err != nil {
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
