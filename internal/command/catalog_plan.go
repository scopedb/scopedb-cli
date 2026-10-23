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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	scopedb "github.com/scopedb/goscopedb"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/spf13/cobra"
)

type catalogPlan struct {
	Version        int             `json:"version"`
	Endpoint       string          `json:"endpoint"`
	WorkspaceID    string          `json:"workspace_id,omitempty"`
	CredentialHash string          `json:"credential_hash,omitempty"`
	Resource       catalogResource `json:"resource"`
	Definition     json.RawMessage `json:"definition"`
	ETag           string          `json:"etag"`
	scopedb.CatalogResult[json.RawMessage]
}

func (a *app) changeCatalog(cmd *cobra.Command, action string, options catalogOptions) error {
	resource, err := options.resource(cmd)
	if err != nil {
		return err
	}
	if action == "drop" && resource.Kind == "catalog" && !options.all {
		return usageError("select a resource to drop, or use --all to clear the tenant")
	}
	var plan catalogPlan
	var method string
	if options.plan != "" {
		data, err := a.readCatalog(cmd.Context(), options.plan)
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
			definition, err := a.readCatalog(cmd.Context(), options.file)
			if err != nil {
				return err
			}
			method, plan.Definition = http.MethodPut, definition
		}
	}
	names, err := plan.Resource.names()
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
	client, err := scopedb.NewClient(scopedb.Config{
		Endpoint: access.Endpoint, APIKey: access.APIKey, HTTPClient: a.httpClient,
		// Use the CLI request budget instead of the SDK's default write timeout.
		WriteTimeout: new(time.Duration),
	})
	if err != nil {
		return err
	}
	defer client.Close()
	catalog := plan.Resource.resolve(client, names)
	mutate := func(ctx context.Context, controls scopedb.CatalogOptions) (scopedb.CatalogResult[json.RawMessage], error) {
		if method == http.MethodDelete {
			return catalog.Delete(ctx, controls)
		}
		return catalog.Apply(ctx, plan.Definition, controls)
	}
	if options.plan != "" {
		if plan.Endpoint != endpoint || plan.WorkspaceID != access.WorkspaceID || plan.CredentialHash != credentialHash {
			return usageError("plan targets a different connection, workspace, or machine credential; select its connection or generate a new plan")
		}
	} else {
		ctx, cancel := timeoutContext(cmd.Context(), options.requestTimeout)
		change, err := mutate(ctx, scopedb.CatalogOptions{DryRun: true})
		cancel()
		if err != nil {
			return err
		}
		plan.Version, plan.Endpoint, plan.WorkspaceID = 1, endpoint, access.WorkspaceID
		plan.CredentialHash = credentialHash
		plan.ETag, plan.CatalogResult = change.ETag, change
		diff, err := catalogDiff(plan.Resource, plan.CatalogResult)
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
		if (diff != "" || plan.Destructive) && !options.yes {
			if err := a.confirmCatalog(cmd.Context(), options.file == "-"); err != nil {
				return err
			}
			options.allowDestructive = options.allowDestructive || plan.Destructive
		}
	}
	if plan.Destructive && !options.allowDestructive {
		return usageError("changes may permanently lose data; review the plan and pass --allow-destructive")
	}
	// Time spent reviewing the diff does not consume the commit timeout.
	ctx, cancel := timeoutContext(cmd.Context(), options.requestTimeout)
	defer cancel()
	result, err := mutate(ctx, scopedb.CatalogOptions{
		AllowDestructive: options.allowDestructive, IfMatch: plan.ETag,
	})
	if err != nil {
		return err
	}
	message := "Applied."
	if action == "drop" {
		message = "Dropped."
	}
	if _, err := fmt.Fprintln(a.errOut, message); err != nil {
		return clierror.Wrap(clierror.ExitGeneral, "catalog applied, but reporting the result failed: "+err.Error(), err)
	}
	if err := writeCatalog(a.out, result, options.format); err != nil {
		return clierror.Wrap(clierror.ExitGeneral, "catalog applied, but writing the result failed: "+err.Error(), err)
	}
	return nil
}

func (a *app) confirmCatalog(ctx context.Context, stdinConsumed bool) error {
	if stdinConsumed || !a.isInputTerminal() {
		return usageError("confirmation requires interactive input; pass --yes or apply a saved plan")
	}
	answer, err := a.readLine(ctx, "Apply these catalog changes? [y/N] ")
	if err != nil {
		return err
	}
	if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
		return clierror.New(clierror.ExitInterrupted, "catalog apply cancelled")
	}
	return nil
}
