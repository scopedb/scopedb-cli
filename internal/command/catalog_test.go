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
	"strings"
	"testing"

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
		require.Equal(t, "/prefix/v1/databases/db/schemas/public/tables/a%2Fb", r.URL.EscapedPath())
		require.Equal(t, http.MethodPut, r.Method)
		var definition map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&definition))
		require.Equal(t, "yes", definition["comment"], "YAML 1.2 plain yes is a string")
		status := http.StatusOK
		body := `{"before":null,"after":{"name":"a/b","columns":[],"comment":"yes"}}`
		if r.URL.Query().Get("dry_run") == "true" {
			plans++
			require.Empty(t, r.Header.Get("If-Match"))
		} else {
			writes++
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
		return root.ExecuteContext(t.Context())
	}
	require.NoError(t, run("name: a/b\ncomment: yes\n", "catalog", "plan", "table", "db.public.`a/b`", "-f", "-"))
	saved := out.String()
	require.NotContains(t, saved, "fixture-secret")
	require.Empty(t, diagnostics.String())
	require.Contains(t, saved, "etag:")
	require.Zero(t, writes)
	require.NoError(t, run(saved, "catalog", "apply", "--plan", "-"))
	require.Equal(t, 1, writes)
	require.Equal(t, 1, plans, "saved plan must not be refreshed before applying")
	require.Contains(t, diagnostics.String(), "+name: a/b")
	require.Contains(t, out.String(), "before: null")
	apiKey = "another-workspace-key"
	err := run(saved, "catalog", "apply", "--plan", "-")
	require.Equal(t, clierror.ExitUsage, clierror.ExitCode(err))
	require.Equal(t, 1, writes, "a saved plan must not cross credential identities at the same endpoint")
	apiKey = "fixture-secret"
	stale = true
	err = run(saved, "catalog", "apply", "--plan", "-")
	require.Error(t, err)
	require.Contains(t, clierror.Render(err), "generate a new plan")
	require.Equal(t, 2, writes, "version conflict must not trigger an automatic retry")
	require.Equal(t, 1, plans)
	require.Empty(t, out.String())
}

func TestCatalogApplyConfirmation(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	definition := filepath.Join(t.TempDir(), "table.yaml")
	require.NoError(t, os.WriteFile(definition, []byte("name: t\ncolumns: []\n"), 0o600))
	for _, tc := range []struct {
		name, input string
		yes         bool
		wantWrites  int
	}{
		{name: "enter", input: "\n", wantWrites: 1},
		{name: "eof", input: "", wantWrites: 0},
		{name: "decline", input: "no\n", wantWrites: 0},
		{name: "automation", yes: true, wantWrites: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writes := 0
			var out, diagnostics bytes.Buffer
			root := NewRoot(Dependencies{In: strings.NewReader(tc.input), Out: &out, ErrOut: &diagnostics,
				IsInputTerminal: func() bool { return !tc.yes },
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
						require.Equal(t, `"1"`, r.Header.Get("If-Match"))
					}
					body := `{"before":{"name":"t","columns":[{"name":"old","data_type":"int"}]},"after":{"name":"t","columns":[]}}`
					return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"1"`}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				})},
			})
			args := []string{"catalog", "apply", "table", "db.public.t", "-f", definition}
			if tc.yes {
				args = append(args, "--yes")
			}
			root.SetArgs(args)
			err := root.ExecuteContext(t.Context())
			if tc.wantWrites == 0 {
				require.Equal(t, clierror.ExitInterrupted, clierror.ExitCode(err))
			} else {
				require.NoError(t, err)
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
		{[]string{"table", "db.public.t"}, http.MethodDelete, "/v1/databases/db/schemas/public/tables/t", "", "null"},
		{[]string{"databases"}, http.MethodPut, "/v1/databases", `{"databases":[]}`, `{"databases":[]}`},
	} {
		t.Run(tc.resource[0], func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			requests := 0
			root := NewRoot(Dependencies{Out: &out, ErrOut: &diagnostics,
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
						require.Equal(t, `"4"`, r.Header.Get("If-Match"))
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"4"`}}, Body: io.NopCloser(strings.NewReader(`{"before":{"name":"t"},"after":` + tc.after + `}`)), Request: r}, nil
				})},
			})
			root.SetArgs(append(append([]string{"catalog", "drop"}, tc.resource...), "--yes", "--format", "json"))
			require.NoError(t, root.ExecuteContext(t.Context()))
			require.Equal(t, 2, requests)
			require.JSONEq(t, `{"before":{"name":"t"},"after":`+tc.after+`}`, out.String())
		})
	}
}

func TestCatalogInvalidInput(t *testing.T) {
	for _, input := range []string{"name: a\nname: b\n", "name: a\n---\nname: b\n", "null", ""} {
		t.Run(input, func(t *testing.T) {
			root := NewRoot(Dependencies{In: strings.NewReader(input), Out: io.Discard, ErrOut: io.Discard})
			root.SetArgs([]string{"catalog", "plan", "table", "db.public.t", "-f", "-"})
			require.Equal(t, clierror.ExitUsage, clierror.ExitCode(root.ExecuteContext(context.Background())))
		})
	}
	a := newApp(Dependencies{In: strings.NewReader("name: t\ncomment: 2026-10-12\nretention_days: 9007199254740993\nzero: 077\neight: 008\nexplicit: !!str 077\nbinary: 0b10\nunderscores: 1_000\nexponent: 1e3\n")})
	data, err := a.readCatalog("-")
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
	for _, tc := range []struct {
		name   string
		status int
		cause  error
		code   int
		apply  bool
	}{
		{name: "proxy unavailable during plan", status: 502, code: clierror.ExitTemporary},
		{name: "cancel apply", cause: context.Canceled, code: clierror.ExitInterrupted, apply: true},
		{name: "timeout apply", cause: context.DeadlineExceeded, code: clierror.ExitTemporary, apply: true},
		{name: "lost apply response", cause: io.ErrUnexpectedEOF, code: clierror.ExitGeneral, apply: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
					if requests == 2 {
						return nil, tc.cause
					}
					status, body := 200, `{"before":null,"after":{"name":"t","columns":[]}}`
					if tc.status != 0 {
						status, body = tc.status, `{"message":"gateway unavailable"}`
					}
					return &http.Response{StatusCode: status, Header: http.Header{"Etag": []string{`"1"`}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				})},
			})
			args := []string{"catalog", "plan", "table", "db.public.t", "-f", "-"}
			if tc.apply {
				args[1] = "apply"
				args = append(args, "--yes")
			}
			root.SetArgs(args)
			err := root.ExecuteContext(t.Context())
			require.Equal(t, tc.code, clierror.ExitCode(err))
			require.Empty(t, out.String())
			if tc.apply {
				require.ErrorIs(t, err, tc.cause)
				require.Equal(t, 2, requests, "an uncertain write must not be retried")
				require.Contains(t, clierror.Render(err), "read the catalog")
			} else {
				require.Equal(t, 1, requests)
			}
		})
	}
}
