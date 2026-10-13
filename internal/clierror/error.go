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
	"strings"
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

func (e *Error) cause() string {
	if e.Err == nil {
		return ""
	}
	message := e.Error()
	err := e.Err
	// A wrapper often repeats the message while the detail sits further down,
	// such as a transport failure inside a control-plane error.
	for {
		cause := err.Error()
		if cause != "" && !strings.Contains(message, cause) {
			if !strings.ContainsAny(cause, "\r\n") {
				return cause
			}
			lines := strings.FieldsFunc(cause, func(r rune) bool { return r == '\r' || r == '\n' })
			for i, line := range lines {
				lines[i] = strings.TrimSpace(line)
			}
			return strings.Join(lines, "; ")
		}
		next := errors.Unwrap(err)
		if next == nil {
			return ""
		}
		err = next
	}
}

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

// Compact writes the message, cause, request ID, and hint as one string for
// reports that list one entry per failure. Callers must never wrap a secret.
func Compact(err error) string {
	var cliErr *Error
	if !errors.As(err, &cliErr) {
		return fmt.Sprint(err)
	}
	parts := []string{cliErr.Error()}
	if cause := cliErr.cause(); cause != "" {
		parts = append(parts, cause)
	}
	if cliErr.RequestID != "" {
		parts = append(parts, "request ID: "+cliErr.RequestID)
	}
	if cliErr.Hint != "" {
		parts = append(parts, cliErr.Hint)
	}
	return strings.Join(parts, "; ")
}

// Render writes a stable, secret-safe error message.
func Render(err error) string {
	var cliErr *Error
	if !errors.As(err, &cliErr) {
		return fmt.Sprintf("Error: %s\n", err)
	}

	if cliErr.Code == ExitInterrupted && cliErr.Hint == "" {
		return "\n"
	}

	lines := fmt.Sprintf("Error: %s\n", cliErr.Error())
	if cause := cliErr.cause(); cause != "" {
		lines += fmt.Sprintf("Caused by: %s\n", cause)
	}
	if cliErr.RequestID != "" {
		lines += fmt.Sprintf("Request ID: %s\n", cliErr.RequestID)
	}
	if cliErr.Hint != "" {
		lines += fmt.Sprintf("Hint: %s\n", cliErr.Hint)
	}
	return lines
}
