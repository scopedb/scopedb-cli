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

package dataplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/scopedb/scopedb-cli/internal/auth"
)

func TestExecuteCancelsSubmittedStatementOnInterrupt(t *testing.T) {
	const statementID = "01989a4e-4ee2-7e63-87a5-65ac3b5161dc"
	getStarted := make(chan struct{})
	var closeOnce sync.Once
	var cancelCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case http.MethodPost + " /v1/statements":
			_, _ = writer.Write([]byte(`{"statement_id":"` + statementID + `","status":"running","created_at":"2026-09-09T00:00:00Z","progress":{}}`))
		case http.MethodGet + " /v1/statements/" + statementID:
			closeOnce.Do(func() { close(getStarted) })
			<-request.Context().Done()
		case http.MethodPost + " /v1/statements/" + statementID + "/cancel":
			cancelCalled.Store(true)
			_, _ = writer.Write([]byte(`{"statement_id":"` + statementID + `","status":"cancelled","created_at":"2026-09-09T00:00:00Z","message":"cancelled by client"}`))
		default:
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-getStarted
		cancel()
	}()
	service := QueryService{HTTPClient: server.Client()}
	_, err := service.Execute(ctx, auth.Access{Endpoint: server.URL, APIKey: "secret"}, "FROM events")
	var interrupted *InterruptedError
	if !errors.As(err, &interrupted) {
		t.Fatalf("Execute() error = %T %v, want *InterruptedError", err, err)
	}
	if interrupted.StatementID != statementID || interrupted.CancelErr != nil {
		t.Errorf("interrupted error = %#v", interrupted)
	}
	if !cancelCalled.Load() {
		t.Fatal("server-side cancel endpoint was not called")
	}
}
