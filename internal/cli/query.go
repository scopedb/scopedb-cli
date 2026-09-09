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

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/fileutil"
	"github.com/scopedb/scopedb-cli/internal/output"
	"github.com/spf13/cobra"
)

const maxStatementBytes = 8 << 20

func (a *app) newQueryCommand() *cobra.Command {
	var statementFile string
	var format string
	var outputPath string
	var force bool
	var timeout time.Duration
	command := &cobra.Command{
		Use:     "query [scopeql]",
		Aliases: []string{"q"},
		Short:   "Execute a ScopeQL statement",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 1 {
				return usageError("query accepts at most one inline statement")
			}
			return nil
		},
		RunE: func(command *cobra.Command, args []string) error {
			if !isQueryFormat(format) {
				return usageError(fmt.Sprintf("unsupported format %q; use table, json, jsonl, or csv", format))
			}
			if timeout < 0 {
				return usageError("--timeout must not be negative")
			}
			statement, err := a.readStatement(args, statementFile)
			if err != nil {
				return err
			}
			runtime, err := a.runtime(command)
			if err != nil {
				return NormalizeError(err)
			}
			access, err := runtime.auth.ResolveDataAccess(command.Context())
			if err != nil {
				return NormalizeError(err)
			}

			queryContext := command.Context()
			cancel := func() {}
			if timeout > 0 {
				queryContext, cancel = context.WithTimeout(queryContext, timeout)
			}
			defer cancel()
			result, err := a.query.Execute(queryContext, access, statement)
			if err != nil {
				return NormalizeError(err)
			}

			if outputPath == "" {
				if err := output.RenderResult(a.out, result, format); err != nil {
					return NormalizeError(err)
				}
				return nil
			}
			if err := writeResultFile(outputPath, force, func(writer io.Writer) error {
				return output.RenderResult(writer, result, format)
			}); err != nil {
				return NormalizeError(err)
			}
			_, err = fmt.Fprintf(a.errOut, "Wrote %d row(s) to %s.\n", result.TotalRows, outputPath)
			return NormalizeError(err)
		},
	}
	command.Flags().StringVar(&statementFile, "file", "", "read ScopeQL from a file; use - for stdin")
	command.Flags().StringVarP(&format, "format", "f", output.FormatTable, "output format: table, json, jsonl, or csv")
	command.Flags().StringVarP(&outputPath, "output", "o", "", "write results to a file")
	command.Flags().BoolVar(&force, "force", false, "overwrite an existing output file")
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

func writeResultFile(path string, force bool, render func(io.Writer) error) error {
	if path == "" {
		return errors.New("output path must not be empty")
	}
	if _, err := os.Stat(path); err == nil && !force {
		return clierror.WithHint(clierror.New(clierror.ExitGeneral, fmt.Sprintf("output file %s already exists", path)), "pass --force to overwrite it")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output file: %w", err)
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".scope-result-*")
	if err != nil {
		return fmt.Errorf("create temporary output file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set output file permissions: %w", err)
	}
	if err := render(temporary); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync output file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close output file: %w", err)
	}
	if err := fileutil.Commit(temporaryPath, path, force); err != nil {
		if !force && errors.Is(err, os.ErrExist) {
			return clierror.WithHint(clierror.New(clierror.ExitGeneral, fmt.Sprintf("output file %s was created concurrently", path)), "choose another path or pass --force")
		}
		return fmt.Errorf("replace output file: %w", err)
	}
	return nil
}
