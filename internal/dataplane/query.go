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

// InterruptedError records cancellation of a submitted server-side statement.
type InterruptedError struct {
	StatementID string
	CancelErr   error
}

func (e *InterruptedError) Error() string {
	if e.StatementID == "" {
		return "query interrupted"
	}
	if e.CancelErr != nil {
		return fmt.Sprintf("query %s interrupted; server cancellation could not be confirmed", e.StatementID)
	}
	return fmt.Sprintf("query %s interrupted", e.StatementID)
}

func (e *InterruptedError) Unwrap() error { return context.Canceled }

// TimedOutError records a client-side deadline after a statement was submitted.
type TimedOutError struct {
	StatementID string
	CancelErr   error
}

func (e *TimedOutError) Error() string {
	if e.StatementID == "" {
		return "query timed out"
	}
	if e.CancelErr != nil {
		return fmt.Sprintf("query %s timed out; server cancellation could not be confirmed", e.StatementID)
	}
	return fmt.Sprintf("query %s timed out", e.StatementID)
}

func (e *TimedOutError) Unwrap() error { return context.DeadlineExceeded }

// QueryService executes ScopeQL through the public Go SDK.
type QueryService struct {
	HTTPClient *http.Client
}

// Execute submits a statement, waits for its result, and best-effort cancels
// the server-side work if the caller interrupts the command.
func (s *QueryService) Execute(ctx context.Context, access auth.Access, statement string) (*scopedb.ResultSet, error) {
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
		return result, nil
	}
	interrupted := errors.Is(err, context.Canceled)
	timedOut := errors.Is(err, context.DeadlineExceeded)
	if !interrupted && !timedOut {
		return nil, err
	}

	cancelCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cancelResult, cancelErr := handle.Cancel(cancelCtx)
	if cancelErr == nil && cancelResult.Status != scopedb.StatementStatusCancelled {
		cancelErr = fmt.Errorf("statement was not cancelled: status %s", cancelResult.Status)
	}
	if timedOut {
		return nil, &TimedOutError{StatementID: handle.ID().String(), CancelErr: cancelErr}
	}
	return nil, &InterruptedError{StatementID: handle.ID().String(), CancelErr: cancelErr}
}
