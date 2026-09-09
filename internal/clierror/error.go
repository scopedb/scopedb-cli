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

package clierror

import (
	"errors"
	"fmt"
)

const (
	ExitOK          = 0
	ExitGeneral     = 1
	ExitUsage       = 2
	ExitAuth        = 3
	ExitNotFound    = 4
	ExitTemporary   = 5
	ExitInterrupted = 130
)

// Error is an error ready to be presented at the CLI boundary.
type Error struct {
	Code      int
	Message   string
	Hint      string
	RequestID string
	Err       error
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "command failed"
}

func (e *Error) Unwrap() error { return e.Err }

// New creates a CLI error with an exit code and user-facing message.
func New(code int, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Wrap creates a CLI error while preserving its cause.
func Wrap(code int, message string, err error) *Error {
	return &Error{Code: code, Message: message, Err: err}
}

// WithHint adds a remediation hint.
func WithHint(err *Error, hint string) *Error {
	err.Hint = hint
	return err
}

// ExitCode returns the process exit code represented by err.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var cliErr *Error
	if errors.As(err, &cliErr) && cliErr.Code != 0 {
		return cliErr.Code
	}
	return ExitGeneral
}

// Render writes a stable, secret-safe error message.
func Render(err error) string {
	var cliErr *Error
	if !errors.As(err, &cliErr) {
		return fmt.Sprintf("Error: %s\n", err)
	}

	message := fmt.Sprintf("Error: %s\n", cliErr.Error())
	if cliErr.RequestID != "" {
		message += fmt.Sprintf("Request ID: %s\n", cliErr.RequestID)
	}
	if cliErr.Hint != "" {
		message += fmt.Sprintf("Hint: %s\n", cliErr.Hint)
	}
	return message
}
