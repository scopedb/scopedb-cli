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
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/output"
	"github.com/spf13/cobra"
)

const maxStatementBytes = 8 << 20

func (a *app) newQueryCommand() *cobra.Command {
	var statementFile string
	var format string
	var timeout time.Duration
	command := &cobra.Command{
		Use:   "query [scopeql]",
		Short: "Execute a ScopeQL statement",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 1 {
				return usageError("query accepts at most one inline statement")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if !isQueryFormat(format) {
				return usageError(fmt.Sprintf("unsupported format %q; use table, json, jsonl, or csv", format))
			}
			if timeout < 0 {
				return usageError("--timeout must not be negative")
			}
			statement, err := readInput(cmd.Context(), func() (string, error) {
				return a.readStatement(args, statementFile)
			})
			if err != nil {
				return err
			}
			runtime, err := a.runtime(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			access, err := runtime.auth.ResolveDataAccess(cmd.Context())
			if err != nil {
				return NormalizeError(err)
			}

			queryContext := cmd.Context()
			cancel := func() {}
			if timeout > 0 {
				queryContext, cancel = context.WithTimeout(queryContext, timeout)
			}
			defer cancel()
			result, err := a.query.Execute(queryContext, access, statement)
			if err != nil {
				return NormalizeError(err)
			}
			if err := output.RenderResult(a.out, result.ResultSet, format); err != nil {
				return clierror.WithHint(clierror.Wrap(clierror.ExitGeneral, fmt.Sprintf("query %s completed, but its results could not be written", result.StatementID), err), "use the statement ID to retrieve its result; do not rerun a statement with side effects")
			}
			return nil
		},
	}
	command.Flags().StringVarP(&statementFile, "file", "f", "", "read ScopeQL from a file; use - for stdin")
	command.Flags().StringVar(&format, "format", output.FormatTable, "output format: table, json, jsonl, or csv")
	command.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "maximum time to wait before cancelling the statement; 0 disables the limit")
	return command
}

func isQueryFormat(value string) bool {
	switch value {
	case output.FormatTable, output.FormatJSON, output.FormatJSONL, output.FormatCSV:
		return true
	default:
		return false
	}
}

func (a *app) readStatement(args []string, statementFile string) (string, error) {
	if len(args) == 1 && statementFile != "" {
		return "", usageError("provide either an inline statement or --file, not both")
	}
	var (
		data []byte
		err  error
	)
	switch {
	case len(args) == 1:
		data = []byte(args[0])
	case statementFile != "" && statementFile != "-":
		data, err = readLimitedFile(statementFile, maxStatementBytes)
	case statementFile == "-" || !a.isInputTerminal():
		data, err = readLimited(a.input, maxStatementBytes)
	default:
		return "", usageError("provide a ScopeQL statement, --file, or piped stdin")
	}
	if err != nil {
		return "", NormalizeError(err)
	}
	statement := strings.TrimSpace(string(data))
	if statement == "" {
		return "", usageError("ScopeQL statement must not be empty")
	}
	return statement, nil
}

func readLimitedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open statement file: %w", err)
	}
	data, readErr := readLimited(file, limit)
	if closeErr := file.Close(); readErr == nil && closeErr != nil {
		return nil, fmt.Errorf("close statement file: %w", closeErr)
	}
	return data, readErr
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read statement: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, usageError(fmt.Sprintf("ScopeQL statement exceeds %d bytes", limit))
	}
	return data, nil
}
