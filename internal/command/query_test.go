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
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	scopedb "github.com/scopedb/goscopedb"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/stretchr/testify/require"
)

func TestQueryWritesResultsToStdout(t *testing.T) {
	for _, timeout := range []string{"", "0", "2m"} {
		t.Run("timeout="+timeout, func(t *testing.T) {
			args := []string{"--format", "json"}
			if timeout != "" {
				args = append(args, "--timeout", timeout)
			}
			submissions := 0
			out, err := runQueryWithTransport(t, func(r *http.Request) (*http.Response, error) {
				require.Equal(t, "POST /v1/statements", r.Method+" "+r.URL.Path)
				deadline, ok := r.Context().Deadline()
				if timeout == "2m" {
					require.True(t, ok)
					require.InDelta(t, 120, time.Until(deadline).Seconds(), 1)
				} else {
					require.False(t, ok, "queries must not impose a wait limit by default or with --timeout 0")
				}
				submissions++
				return finishedQueryResponse(r), nil
			}, args...)
			require.NoError(t, err)
			require.Equal(t, 1, submissions)
			require.JSONEq(t, `[{"ready":1}]`, out)
		})
	}
}

func TestQueryWaitLimitExpires(t *testing.T) {
	out, err := runQueryWithTransport(t, func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	}, "--timeout", "20ms")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, clierror.ExitTemporary, clierror.ExitCode(err))
	require.Empty(t, out)
}

func TestQueryFailureDoesNotWriteResults(t *testing.T) {
	out, err := runQueryWithTransport(t, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("fixture query failure")
	}, "--format", "json")
	require.ErrorContains(t, err, "fixture query failure")
	require.NotContains(t, clierror.Render(err), "completed")
	require.Empty(t, out)
}

func runQueryWithTransport(t *testing.T, transport roundTripFunc, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runQueryWithWriter(t, transport, &out, args...)
	require.NotContains(t, out.String(), "fixture-secret")
	return out.String(), err
}

func runQueryWithWriter(t *testing.T, transport roundTripFunc, out io.Writer, args ...string) error {
	t.Helper()
	fake, _ := setupDataPlaneLogin(t, "https://data.example.com")
	var diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		Out: out, ErrOut: &diagnostics,
		HTTPClient: fake.dataClient(transport),
	})
	root.SetArgs(append([]string{"query", "SELECT 1 AS ready"}, args...))
	err := NormalizeError(root.ExecuteContext(t.Context()))
	require.NotContains(t, diagnostics.String()+clierror.Render(err), "fixture-secret")
	return err
}

func finishedQueryResponse(r *http.Request) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"statement_id":"01989a4e-4ee2-7e63-87a5-65ac3b5161dc","status":"finished","created_at":"2026-09-09T00:00:00Z","progress":{},"result_set":{"metadata":{"fields":[{"name":"ready","data_type":"int"}],"num_rows":1},"format":"json","rows":[["1"]]}}`)),
		Request:    r,
	}
}

func TestQueryReportsCompletionWhenStdoutFails(t *testing.T) {
	for _, format := range []string{"table", "json", "jsonl", "csv"} {
		t.Run(format, func(t *testing.T) {
			writeErr := errors.New("output is full")
			submissions := 0
			err := runQueryWithWriter(t, func(r *http.Request) (*http.Response, error) {
				require.Equal(t, "POST /v1/statements", r.Method+" "+r.URL.Path)
				submissions++
				return finishedQueryResponse(r), nil
			}, failingWriter{writeErr}, "--format", format)
			require.ErrorIs(t, err, writeErr)
			require.Equal(t, clierror.ExitGeneral, clierror.ExitCode(err))
			require.Equal(t, 1, submissions)
			require.Contains(t, clierror.Render(err), "query 01989a4e-4ee2-7e63-87a5-65ac3b5161dc completed")
			require.Contains(t, clierror.Render(err), "do not rerun a statement with side effects")
		})
	}
}

func TestQueryReportsStatementFailure(t *testing.T) {
	const statementID = "01989a4e-4ee2-7e63-87a5-65ac3b5161dc"
	for _, status := range []string{"failed", "cancelled"} {
		for _, phase := range []string{"submit", "poll"} {
			t.Run(status+"/"+phase, func(t *testing.T) {
				requests := 0
				out, err := runQueryWithTransport(t, func(r *http.Request) (*http.Response, error) {
					requests++
					responseStatus := status
					if requests == 1 {
						require.Equal(t, "POST /v1/statements", r.Method+" "+r.URL.Path)
						if phase == "poll" {
							responseStatus = "running"
						}
					} else {
						require.Equal(t, "GET /v1/statements/"+statementID, r.Method+" "+r.URL.Path)
					}
					body := `{"statement_id":"` + statementID + `","status":"` + responseStatus + `","created_at":"2026-09-09T00:00:00Z","progress":{}`
					if responseStatus == "failed" {
						body += `,"error":{"code":"statement_failed","message":"unknown function UNKNOWN_FUNCTION","details":{"line":1}}`
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body + `}`)), Request: r}, nil
				}, "--format", "json")
				require.Equal(t, clierror.ExitGeneral, clierror.ExitCode(err))
				require.Empty(t, out)
				if phase == "submit" {
					require.Equal(t, 1, requests)
				} else {
					require.Equal(t, 2, requests)
				}
				rendered := clierror.Render(err)
				if status == "failed" {
					require.Contains(t, rendered, "unknown function UNKNOWN_FUNCTION")
					var failure *scopedb.Error
					require.ErrorAs(t, err, &failure)
					require.Equal(t, "statement_failed", failure.Code)
					require.JSONEq(t, `{"line":1}`, string(failure.Details))
				} else {
					require.Contains(t, rendered, statementID)
					require.Contains(t, rendered, "cancelled")
					require.NotErrorIs(t, err, context.Canceled)
				}
			})
		}
	}
}

func TestQueryTimeoutReportsServerCancellation(t *testing.T) {
	const statementID = "01989a4e-4ee2-7e63-87a5-65ac3b5161dc"
	for _, cancelStatus := range []string{"cancelled", "finished", "failed", "pending", "running", "unavailable", "malformed"} {
		t.Run(cancelStatus, func(t *testing.T) {
			cancelCalls, fetchCalls := 0, 0
			out, err := runQueryWithTransport(t, func(r *http.Request) (*http.Response, error) {
				status := http.StatusOK
				body := `{"statement_id":"` + statementID + `","status":"running","created_at":"2026-09-09T00:00:00Z","progress":{}}`
				switch r.Method + " " + r.URL.Path {
				case "POST /v1/statements":
				case "GET /v1/statements/" + statementID:
					fetchCalls++
					return nil, context.DeadlineExceeded
				case "POST /v1/statements/" + statementID + "/cancel":
					cancelCalls++
					require.NoError(t, r.Context().Err(), "server cancellation must have a fresh context")
					require.Equal(t, "json", r.URL.Query().Get("format"))
					body = `{"statement_id":"` + statementID + `","status":"` + cancelStatus + `","created_at":"2026-09-09T00:00:00Z","progress":{}`
					switch cancelStatus {
					case "finished":
						body += `,"result_set":{"metadata":{"fields":[{"name":"ready","data_type":"int"}],"num_rows":1},"format":"json","rows":[["1"]]}`
					case "failed":
						body += `,"error":{"code":"statement_failed","message":"unknown function UNKNOWN_FUNCTION"}`
					}
					body += `}`
					switch cancelStatus {
					case "unavailable":
						status = http.StatusServiceUnavailable
						body = `{"code":"unavailable","message":"unavailable"}`
					case "malformed":
						body = `{"status":"cancelled"}`
					}
				default:
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			}, "--format", "json")
			require.Equal(t, clierror.ExitTemporary, clierror.ExitCode(err))
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.Equal(t, 1, cancelCalls)
			require.Equal(t, 1, fetchCalls, "cancellation already returns the complete outcome")
			require.Empty(t, out)
			rendered := clierror.Render(err)
			require.Contains(t, rendered, statementID)
			switch cancelStatus {
			case "cancelled":
				require.Contains(t, rendered, "server cancellation confirmed")
				require.NotContains(t, rendered, "increase --timeout")
				require.NotContains(t, rendered, "could not be confirmed")
			case "finished":
				require.Contains(t, rendered, "statement already completed")
				require.Contains(t, rendered, "do not rerun a statement with side effects")
				require.NotContains(t, rendered, "could not be confirmed")
			case "failed":
				require.Contains(t, rendered, "statement failed: unknown function UNKNOWN_FUNCTION")
				require.NotContains(t, rendered, "could not be confirmed")
				require.NotContains(t, rendered, "retry")
			default:
				require.Contains(t, rendered, "server cancellation could not be confirmed")
				require.Contains(t, rendered, "verify the statement's outcome before retrying")
				require.NotContains(t, rendered, "increase --timeout and retry")
			}
		})
	}
}
