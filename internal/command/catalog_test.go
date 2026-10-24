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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/go-openapi/go-yaml"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/stretchr/testify/require"
)

func TestCatalogPlanApply(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	var out, diagnostics bytes.Buffer
	writes, plans := 0, 0
	stale := false
	apiKey := "fixture-secret"
	client := &http.Client{Transport: doctorTransport(func(r *http.Request) (*http.Response, error) {
		require.Equal(t, "Bearer fixture-secret", r.Header.Get("Authorization"))
		require.Equal(t, "/prefix/v1/catalog/databases/db/schemas/public/tables/a%2Fb", r.URL.EscapedPath())
		require.Equal(t, http.MethodPut, r.Method)
		var definition map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&definition))
		require.Equal(t, "yes", definition["comment"], "YAML 1.2 plain yes is a string")
		require.Equal(t, map[string]any{"secret_access_key": "storage-secret"}, definition["storage"], "saved plans must preserve the submitted definition")
		status := http.StatusOK
		body := `{"before":{"name":"a/b","columns":[{"name":"old","data_type":"int"}]},"after":{"name":"a/b","columns":[],"comment":"yes"},"destructive":true}`
		if r.URL.Query().Get("dry_run") == "true" {
			plans++
			require.Empty(t, r.Header.Get("If-Match"))
		} else {
			writes++
			require.Equal(t, "true", r.URL.Query().Get("allow_destructive"))
			require.Equal(t, `"7"`, r.Header.Get("If-Match"))
			if stale {
				status = http.StatusPreconditionFailed
				body = `{"code":"catalog_version_mismatch","message":"catalog changed"}`
			}
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Etag": []string{`"7"`}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	run := func(input string, args ...string) error {
		out.Reset()
		diagnostics.Reset()
		root := NewRoot(Dependencies{In: strings.NewReader(input), Out: &out, ErrOut: &diagnostics, HTTPClient: client,
			Getenv: func(name string) string {
				switch name {
				case "SCOPEDB_ENDPOINT":
					return "https://data.example.com/prefix/"
				case "SCOPEDB_API_KEY":
					return apiKey
				}
				return ""
			}, IsInputTerminal: func() bool { return false },
		})
		root.SetArgs(args)
		return NormalizeError(root.ExecuteContext(t.Context()))
	}
	require.NoError(t, run("name: a/b\ncomment: yes\nstorage:\n  secret_access_key: storage-secret\n", "catalog", "plan", "--table", "db.public.`a/b`", "-f", "-"))
	saved := out.String()
	require.NotContains(t, saved, "fixture-secret")
	require.NotContains(t, diagnostics.String(), "storage-secret")
	require.Contains(t, diagnostics.String(), "+++ table db.public.`a/b` after")
	require.Contains(t, saved, "etag:")
	require.Zero(t, writes)
	require.ErrorContains(t, run(saved, "catalog", "apply", "--plan", "-"), "--allow-destructive")
	require.Zero(t, writes)
	require.Contains(t, saved, "destructive: true")
	require.NoError(t, run(saved, "catalog", "apply", "--plan", "-", "--allow-destructive"))
	require.Equal(t, 1, writes)
	require.Equal(t, 1, plans, "saved plan must not be refreshed before applying")
	require.Equal(t, "Applied.\n", diagnostics.String(), "saved plans apply without redisplaying the reviewed diff")
	require.Contains(t, out.String(), "destructive: true")
	apiKey = "another-workspace-key"
	err := run(saved, "catalog", "apply", "--plan", "-")
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	require.Equal(t, 1, writes, "a saved plan must not cross credential identities at the same endpoint")
	apiKey = "fixture-secret"
	stale = true
	err = run(saved, "catalog", "apply", "--plan", "-", "--allow-destructive")
	require.Error(t, err)
	require.Contains(t, clierror.Render(err), "generate a new plan")
	require.Contains(t, clierror.Render(err), "HTTP 412: catalog_version_mismatch")
	require.Equal(t, 2, writes, "version conflict must not trigger an automatic retry")
	require.Equal(t, 1, plans)
	require.Empty(t, out.String())
}

func TestCatalogApplyConfirmation(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	definition := filepath.Join(t.TempDir(), "table.yaml")
	require.NoError(t, os.WriteFile(definition, []byte("name: t\ncolumns: []\n"), 0o600))
	for _, tc := range []struct {
		name, input                                        string
		yes, destructive, allowDestructive, nonInteractive bool
		wantCode                                           int
		wantWrites                                         int
	}{
		{name: "enter declines", input: "\n", destructive: true, wantCode: clierror.ExitInterrupted},
		{name: "yes", input: "yes\n", destructive: true, wantWrites: 1},
		{name: "y", input: "y\n", wantWrites: 1},
		{name: "non-interactive input cannot confirm", input: "yes\n", nonInteractive: true, wantCode: clierror.ExitUsage},
		{name: "eof", input: "", destructive: true, wantCode: clierror.ExitInterrupted},
		{name: "decline", input: "no\n", destructive: true, wantCode: clierror.ExitInterrupted},
		{name: "safe automation", yes: true, wantWrites: 1},
		{name: "destructive automation denied", yes: true, destructive: true, wantCode: clierror.ExitUsage},
		{name: "destructive automation allowed", yes: true, destructive: true, allowDestructive: true, wantWrites: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writes := 0
			var out, diagnostics bytes.Buffer
			root := NewRoot(Dependencies{In: strings.NewReader(tc.input), Out: &out, ErrOut: &diagnostics,
				IsInputTerminal: func() bool { return !tc.yes && !tc.nonInteractive },
				Getenv: func(name string) string {
					switch name {
					case "SCOPEDB_ENDPOINT":
						return "https://data.example.com"
					case "SCOPEDB_API_KEY":
						return "fixture-secret"
					}
					return ""
				},
				HTTPClient: &http.Client{Transport: doctorTransport(func(r *http.Request) (*http.Response, error) {
					if r.URL.Query().Get("dry_run") != "true" {
						writes++
						require.Equal(t, tc.destructive, r.URL.Query().Get("allow_destructive") == "true")
						require.Equal(t, `"1"`, r.Header.Get("If-Match"))
					}
					body := `{"before":{"name":"t","columns":[{"name":"old","data_type":"int"}]},"after":{"name":"t","columns":[]},"destructive":` + strconv.FormatBool(tc.destructive) + `}`
					return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"1"`}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				})},
			})
			args := []string{"catalog", "apply", "--table", "db.public.t", "-f", definition}
			if tc.yes {
				args = append(args, "--yes")
			}
			if tc.allowDestructive {
				args = append(args, "--allow-destructive")
			}
			root.SetArgs(args)
			err := NormalizeError(root.ExecuteContext(t.Context()))
			if tc.wantWrites == 0 {
				require.Equal(t, tc.wantCode, clierror.ExitCode(err))
			} else {
				require.NoError(t, err)
			}
			if tc.destructive {
				require.Contains(t, diagnostics.String(), "permanently lose data")
			}
			require.Equal(t, tc.wantWrites, writes)
			require.Contains(t, diagnostics.String(), "-- name: old")
		})
	}
}

func TestCatalogDrop(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	for _, tc := range []struct {
		resource                  []string
		method, path, body, after string
	}{
		{[]string{"--table", "db.public.t"}, http.MethodDelete, "/v1/catalog/databases/db/schemas/public/tables/t", "", "null"},
		{[]string{"--all"}, http.MethodPut, "/v1/catalog", `{"databases":[]}`, `{"databases":[]}`},
	} {
		t.Run(tc.resource[0], func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			requests := 0
			deps := Dependencies{Out: &out, ErrOut: &diagnostics,
				Getenv: func(name string) string {
					switch name {
					case "SCOPEDB_ENDPOINT":
						return "https://data.example.com"
					case "SCOPEDB_API_KEY":
						return "fixture-secret"
					}
					return ""
				},
				HTTPClient: &http.Client{Transport: doctorTransport(func(r *http.Request) (*http.Response, error) {
					requests++
					require.Equal(t, tc.method, r.Method)
					require.Equal(t, tc.path, r.URL.Path)
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					require.Equal(t, tc.body, string(body))
					if requests == 1 {
						require.Equal(t, "true", r.URL.Query().Get("dry_run"))
					} else {
						require.Equal(t, "true", r.URL.Query().Get("allow_destructive"))
						require.Equal(t, `"4"`, r.Header.Get("If-Match"))
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"4"`}}, Body: io.NopCloser(strings.NewReader(`{"before":{"name":"t"},"after":` + tc.after + `,"destructive":true}`)), Request: r}, nil
				})},
			}
			root := NewRoot(deps)
			root.SetArgs(append(append([]string{"catalog", "drop"}, tc.resource...), "--yes", "--allow-destructive", "--format", "json"))
			require.NoError(t, root.ExecuteContext(t.Context()))
			require.Equal(t, 2, requests)
			require.JSONEq(t, `{"before":{"name":"t"},"after":`+tc.after+`,"destructive":true}`, out.String())
		})
	}
}

func TestCatalogInvalidInput(t *testing.T) {
	for _, input := range []string{"name: a\nname: b\n", "name: a\n---\nname: b\n", "null", ""} {
		t.Run(input, func(t *testing.T) {
			root := NewRoot(Dependencies{In: strings.NewReader(input), Out: io.Discard, ErrOut: io.Discard})
			root.SetArgs([]string{"catalog", "plan", "--table", "db.public.t", "-f", "-"})
			require.Equal(t, clierror.ExitUsage, clierror.ExitCode(root.ExecuteContext(context.Background())))
		})
	}
	a := newApp(Dependencies{In: strings.NewReader("name: t\ncomment: 2026-10-12\nretention_days: 9007199254740993\nzero: 077\neight: 008\nexplicit: !!str 077\nbinary: 0b10\nunderscores: 1_000\nexponent: 1e3\n")})
	data, err := a.readCatalog(t.Context(), "-")
	require.NoError(t, err)
	require.JSONEq(t, `{"name":"t","comment":"2026-10-12","retention_days":9007199254740993,"zero":77,"eight":8,"explicit":"077","binary":"0b10","underscores":"1_000","exponent":1000}`, string(data))
	var out bytes.Buffer
	require.NoError(t, writeCatalog(&out, data, "yaml"))
	converted, err := yaml.ToJSON(out.Bytes())
	require.NoError(t, err)
	require.JSONEq(t, string(data), string(converted))
	require.Contains(t, string(data), "9007199254740993")
	require.Contains(t, string(converted), "9007199254740993")
}

func TestCatalogRequestFailures(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Run("invalid endpoint", func(t *testing.T) {
		t.Setenv("SCOPEDB_ENDPOINT", "not-a-url")
		t.Setenv("SCOPEDB_API_KEY", "fixture-secret")
		root := NewRoot(Dependencies{Out: io.Discard, ErrOut: io.Discard})
		root.SetArgs([]string{"catalog", "get"})
		err := NormalizeError(root.ExecuteContext(t.Context()))
		require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	})
	for _, tc := range []struct {
		name, action    string
		status          int
		cause           error
		code            int
		partial         bool
		invalidResponse bool
	}{
		{name: "proxy unavailable during plan", action: "plan", status: 502, code: clierror.ExitTemporary},
		{name: "cancel apply", action: "apply", cause: context.Canceled, code: clierror.ExitInterrupted},
		{name: "timeout apply", action: "apply", cause: context.DeadlineExceeded, code: clierror.ExitTemporary},
		{name: "lost apply response", action: "apply", cause: io.ErrUnexpectedEOF, code: clierror.ExitGeneral},
		{name: "partial apply response", action: "apply", cause: io.ErrUnexpectedEOF, code: clierror.ExitGeneral, partial: true},
		{name: "partial version conflict", action: "apply", status: 412, cause: io.ErrUnexpectedEOF, code: clierror.ExitGeneral, partial: true},
		{name: "invalid apply response", action: "apply", code: clierror.ExitGeneral, invalidResponse: true},
		{name: "cancel get body", action: "get", cause: context.Canceled, code: clierror.ExitInterrupted, partial: true},
		{name: "cancel plan body", action: "plan", cause: context.Canceled, code: clierror.ExitInterrupted, partial: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apply := tc.action == "apply"
			var out, diagnostics bytes.Buffer
			requests := 0
			root := NewRoot(Dependencies{In: strings.NewReader("name: t\n"), Out: &out, ErrOut: &diagnostics,
				Getenv: func(name string) string {
					switch name {
					case "SCOPEDB_ENDPOINT":
						return "https://data.example.com"
					case "SCOPEDB_API_KEY":
						return "fixture-secret"
					}
					return ""
				},
				HTTPClient: &http.Client{Transport: doctorTransport(func(r *http.Request) (*http.Response, error) {
					requests++
					if apply && requests == 1 {
						return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"1"`}}, Body: io.NopCloser(strings.NewReader(`{"before":null,"after":{"name":"t","columns":[]},"destructive":false}`)), Request: r}, nil
					}
					if tc.cause != nil && !tc.partial {
						return nil, tc.cause
					}
					status, body := 200, `{"before":null,"after":{"name":"t","columns":[]},"destructive":false}`
					if tc.status != 0 {
						status, body = tc.status, `{"message":"gateway unavailable"}`
					}
					if tc.invalidResponse {
						body = `{}`
					}
					response := &http.Response{StatusCode: status, Header: http.Header{"Etag": []string{`"1"`}, "X-Request-Id": []string{"catalog-request"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}
					if tc.partial {
						response.Body = io.NopCloser(iotest.ErrReader(tc.cause))
					}
					return response, nil
				})},
			})
			args := []string{"catalog", tc.action, "--table", "db.public.t"}
			if tc.action != "get" {
				args = append(args, "-f", "-")
			}
			if apply {
				args = append(args, "--yes")
			}
			root.SetArgs(args)
			err := NormalizeError(root.ExecuteContext(t.Context()))
			require.Equal(t, tc.code, clierror.ExitCode(err))
			require.Empty(t, out.String())
			if tc.cause != nil {
				require.ErrorIs(t, err, tc.cause)
			}
			if tc.partial || tc.invalidResponse {
				var failure *clierror.Error
				require.ErrorAs(t, err, &failure)
				require.Equal(t, "catalog-request", failure.RequestID)
				require.Contains(t, failure.Message, "HTTP ")
			}
			if apply {
				require.Equal(t, 2, requests, "an uncertain write must not be retried")
				if tc.status == 412 {
					require.Contains(t, clierror.Render(err), "generate a new plan")
					require.NotContains(t, clierror.Render(err), "catalog_commit_outcome_unknown")
				} else {
					require.Contains(t, clierror.Render(err), "read the catalog")
				}
			} else {
				require.Equal(t, 1, requests)
			}
		})
	}
}

func TestCatalogBrowse(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_ENDPOINT", "https://data.example.com")
	t.Setenv("SCOPEDB_API_KEY", "fixture-secret")
	tableName := "Events.a/b`c\\d"
	table := map[string]any{"name": tableName, "columns": []any{map[string]any{"name": "id", "data_type": "int"}}}
	schema := map[string]any{"name": "public", "tables": []any{table}, "views": []any{map[string]any{"name": "recent", "statement": "from events"}}}
	database := map[string]any{"name": "db", "schemas": []any{schema}}
	document := map[string]any{"databases": []any{database, map[string]any{"name": "empty", "schemas": []any{}}}}
	responses := map[string]any{
		"/v1/catalog":                                                 document,
		"/v1/catalog/databases/db":                                    database,
		"/v1/catalog/databases/db/schemas/public":                     schema,
		"/v1/catalog/databases/empty":                                 map[string]any{"name": "empty", "schemas": []any{}},
		"/v1/catalog/databases/db/schemas/public/tables/" + tableName: table,
	}
	var out, diagnostics bytes.Buffer
	run := func(args ...string) {
		out.Reset()
		diagnostics.Reset()
		requests := 0
		root := NewRoot(Dependencies{Out: &out, ErrOut: &diagnostics, HTTPClient: &http.Client{Transport: doctorTransport(func(r *http.Request) (*http.Response, error) {
			requests++
			require.Equal(t, http.MethodGet, r.Method)
			response, ok := responses[r.URL.Path]
			require.True(t, ok, r.URL.Path)
			body, err := json.Marshal(response)
			require.NoError(t, err)
			return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"1"`}}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
		})}})
		root.SetArgs(append([]string{"catalog"}, args...))
		require.NoError(t, root.ExecuteContext(t.Context()))
		require.Equal(t, 1, requests)
		require.Empty(t, diagnostics.String())
	}
	run("get", "--format", "json")
	exported := out.String()
	encoded, err := json.Marshal(document)
	require.NoError(t, err)
	require.JSONEq(t, string(encoded), exported)
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"databases"}, []string{"db", "empty"}},
		{[]string{"schemas"}, []string{"db.public"}},
		{[]string{"views"}, []string{"db.public.recent"}},
		{[]string{"schemas", "--database", "db"}, []string{"db.public"}},
		{[]string{"views", "--schema", "db.public"}, []string{"db.public.recent"}},
		{[]string{"tables", "--database", "empty"}, []string{}},
	} {
		run(append(append([]string{"list"}, tc.args...), "--format", "json")...)
		var names []string
		require.NoError(t, json.Unmarshal(out.Bytes(), &names))
		require.Equal(t, tc.want, names)
	}
	// Listed names must address the same object, including quoting and HTTP escaping.
	for _, scope := range [][]string{nil, {"--database", "db"}, {"--schema", "db.public"}} {
		run(append([]string{"list", "tables"}, scope...)...)
		data, err := yaml.ToJSON(out.Bytes())
		require.NoError(t, err)
		var names []string
		require.NoError(t, json.Unmarshal(data, &names))
		require.Len(t, names, 1)
		run("get", "--table", names[0], "--format", "json")
		expected, err := json.Marshal(table)
		require.NoError(t, err)
		require.JSONEq(t, string(expected), out.String())
	}
}

func TestCatalogTenantApply(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_ENDPOINT", "https://data.example.com")
	t.Setenv("SCOPEDB_API_KEY", "fixture-secret")
	var out, diagnostics bytes.Buffer
	requests := 0
	root := NewRoot(Dependencies{In: strings.NewReader("databases: []\n"), Out: &out, ErrOut: &diagnostics,
		HTTPClient: &http.Client{Transport: doctorTransport(func(r *http.Request) (*http.Response, error) {
			requests++
			require.Equal(t, http.MethodPut, r.Method)
			require.Equal(t, "/v1/catalog", r.URL.Path)
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.JSONEq(t, `{"databases":[]}`, string(body))
			if requests == 1 {
				require.Equal(t, "true", r.URL.Query().Get("dry_run"))
			} else {
				require.Equal(t, `"9"`, r.Header.Get("If-Match"))
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"9"`}}, Body: io.NopCloser(strings.NewReader(`{"before":{"databases":[{"name":"db"}]},"after":{"databases":[]},"destructive":false}`)), Request: r}, nil
		})},
	})
	root.SetArgs([]string{"catalog", "apply", "-f", "-", "--yes", "--format", "json"})
	require.NoError(t, root.ExecuteContext(t.Context()))
	require.Equal(t, 2, requests)
	require.Contains(t, diagnostics.String(), "-databases:")
	require.JSONEq(t, `{"before":{"databases":[{"name":"db"}]},"after":{"databases":[]},"destructive":false}`, out.String())
}

func TestCatalogScopes(t *testing.T) {
	for _, args := range [][]string{
		{"get", "--table", "events"},
		{"get", "--schema", "db.public", "--table", "db.public.events"},
		{"get", "--database", ""},
		{"apply", "--plan", "plan.yaml", "--table", "db.public.events"},
		{"drop"},
		{"drop", "--all", "--database", "db"},
		{"list", "databases", "--schema", "db.public"},
		{"list", "databases", "--database", "db"},
		{"list", "schemas", "--schema", "db.public"},
		{"list", "tables", "--table", "db.public.t"},
		{"list", "tables", "--view", "db.public.v"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root := NewRoot(Dependencies{Out: io.Discard, ErrOut: io.Discard})
			root.SetArgs(append([]string{"catalog"}, args...))
			require.Equal(t, clierror.ExitUsage, clierror.ExitCode(root.ExecuteContext(t.Context())))
		})
	}
}

func TestCatalogOutput(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_ENDPOINT", "https://data.example.com")
	t.Setenv("SCOPEDB_API_KEY", "fixture-secret")
	var out, diagnostics bytes.Buffer
	writes := 0
	result := `{"before":{"databases":[]},"after":{"databases":[{"name":"db"}]},"destructive":false}`
	client := &http.Client{Transport: doctorTransport(func(r *http.Request) (*http.Response, error) {
		body := result
		if r.Method == http.MethodGet {
			body = `{"databases":[{"name":"db"}]}`
		} else if r.URL.Query().Get("dry_run") != "true" {
			writes++
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"1"`}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	run := func(writer io.Writer, args ...string) error {
		out.Reset()
		diagnostics.Reset()
		root := NewRoot(Dependencies{In: strings.NewReader("databases: [{name: db}]\n"), Out: writer, ErrOut: &diagnostics, HTTPClient: client})
		root.SetArgs(append([]string{"catalog"}, args...))
		return NormalizeError(root.ExecuteContext(t.Context()))
	}
	require.NoError(t, run(&out, "plan", "-f", "-", "--format", "json"))
	var plan catalogPlan
	require.NoError(t, json.Unmarshal(out.Bytes(), &plan))
	require.Equal(t, "catalog", plan.Resource.Kind)
	require.Equal(t, `"1"`, plan.ETag)
	require.Contains(t, diagnostics.String(), "+- name: db")
	path := filepath.Join(t.TempDir(), "plan.json")
	require.NoError(t, os.WriteFile(path, out.Bytes(), 0o600))

	require.NoError(t, run(&out, "apply", "--plan", path, "--format", "json"))
	require.JSONEq(t, result, out.String())
	require.Equal(t, "Applied.\n", diagnostics.String())
	require.Equal(t, 1, writes)

	err := run(failingWriter{err: io.ErrClosedPipe}, "apply", "--plan", path)
	require.ErrorIs(t, err, io.ErrClosedPipe)
	require.Contains(t, clierror.Render(err), "catalog applied, but writing the result failed")
	require.Equal(t, 2, writes, "output failure must not retry a committed request")

	require.NoError(t, run(&out, "get", "--format", "json"))
	require.JSONEq(t, `{"databases":[{"name":"db"}]}`, out.String())
	require.Empty(t, diagnostics.String())
}

func TestCatalogRequestTimeout(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_ENDPOINT", "https://data.example.com")
	t.Setenv("SCOPEDB_API_KEY", "fixture-secret")
	for _, tc := range []struct {
		args     []string
		timeout  time.Duration
		requests int
	}{
		{[]string{"get", "--request-timeout", "2m"}, 2 * time.Minute, 1},
		{[]string{"plan", "-f", "-", "--request-timeout", "2m"}, 2 * time.Minute, 1},
		{[]string{"apply", "-f", "-", "--yes", "--request-timeout", "2m"}, 2 * time.Minute, 2},
		{[]string{"drop", "--table", "db.public.t", "--yes", "--request-timeout", "2m"}, 2 * time.Minute, 2},
		{[]string{"apply", "-f", "-", "--yes"}, 5 * time.Minute, 2},
		{[]string{"get", "--request-timeout", "0"}, 0, 1},
		{[]string{"list", "databases", "--request-timeout", "0"}, 0, 1},
		{[]string{"plan", "-f", "-", "--request-timeout", "0"}, 0, 1},
		{[]string{"apply", "-f", "-", "--yes", "--request-timeout", "0"}, 0, 2},
		{[]string{"drop", "--table", "db.public.t", "--yes", "--request-timeout", "0"}, 0, 2},
		{[]string{"get", "--request-timeout", "-1s"}, 0, 0},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			requests := 0
			root := NewRoot(Dependencies{In: strings.NewReader("databases: []\n"), Out: io.Discard, ErrOut: io.Discard,
				HTTPClient: &http.Client{Transport: doctorTransport(func(r *http.Request) (*http.Response, error) {
					requests++
					deadline, ok := r.Context().Deadline()
					if tc.timeout == 0 {
						require.False(t, ok, "the SDK must not add a deadline when the request limit is disabled")
					} else {
						require.True(t, ok)
						require.InDelta(t, tc.timeout.Seconds(), time.Until(deadline).Seconds(), 5,
							"preview and commit must each receive the configured request budget")
					}
					body := `{"before":{"databases":[]},"after":{"databases":[{"name":"db"}]},"destructive":false}`
					if r.Method == http.MethodGet {
						body = `{"databases":[]}`
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"1"`}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				})},
			})
			root.SetArgs(append([]string{"catalog"}, tc.args...))
			err := NormalizeError(root.ExecuteContext(t.Context()))
			if tc.requests == 0 {
				require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.requests, requests)
		})
	}
}
