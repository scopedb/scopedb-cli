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
	"fmt"
	"net/http"
	"time"

	scopedb "github.com/scopedb/goscopedb"
	"github.com/scopedb/scopedb-cli/internal/auth"
)

// InterruptedError records a client interruption or timeout and the server's
// response to the subsequent cancellation request.
type InterruptedError struct {
	StatementID  string
	Cause        error
	CancelResult *scopedb.StatementSnapshot
	CancelErr    error
}

func (e *InterruptedError) Error() string {
	reason := "interrupted"
	if errors.Is(e.Cause, context.DeadlineExceeded) {
		reason = "timed out"
	}
	if e.StatementID == "" {
		return "query " + reason
	}
	message := fmt.Sprintf("query %s %s", e.StatementID, reason)
	if e.CancelErr != nil {
		return fmt.Sprintf("%s; server cancellation could not be confirmed: %v", message, e.CancelErr)
	}
	switch e.CancelResult.Status {
	case scopedb.StatementStatusCancelled:
		return message + "; server cancellation confirmed"
	case scopedb.StatementStatusFinished:
		return message + "; statement already completed"
	case scopedb.StatementStatusFailed:
		return message + "; statement failed: " + e.CancelResult.Error.Message
	default:
		return fmt.Sprintf("%s; server cancellation could not be confirmed (status %s)", message, e.CancelResult.Status)
	}
}

func (e *InterruptedError) Unwrap() error { return e.Cause }

// QueryService executes ScopeQL through the public Go SDK.
type QueryService struct {
	HTTPClient *http.Client
}

// QueryResult retains the statement ID so output failures can identify a completed query.
type QueryResult struct {
	*scopedb.ResultSet
	StatementID string
}

// Execute submits a statement, waits for its result, and best-effort cancels
// the server-side work if the caller interrupts the command or its wait times out.
func (s *QueryService) Execute(ctx context.Context, access auth.Access, statement string) (*QueryResult, error) {
	client, err := scopedb.NewClient(scopedb.Config{
		Endpoint:   access.Endpoint,
		APIKey:     access.APIKey,
		HTTPClient: s.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()

	handle, err := client.Statement(statement).Submit(ctx)
	if err != nil {
		return nil, err
	}
	result, err := handle.Wait(ctx)
	if err == nil {
		return &QueryResult{ResultSet: result, StatementID: handle.ID().String()}, nil
	}
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}

	cancelCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cancelResult, cancelErr := handle.Cancel(cancelCtx)
	return nil, &InterruptedError{
		StatementID:  handle.ID().String(),
		Cause:        err,
		CancelResult: cancelResult,
		CancelErr:    cancelErr,
	}
}
