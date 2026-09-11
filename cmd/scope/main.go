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

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/command"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := command.NewRoot(command.Dependencies{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	})
	err := command.NormalizeError(root.ExecuteContext(ctx))
	if err == nil {
		return clierror.ExitOK
	}
	_, _ = fmt.Fprint(os.Stderr, renderError(err))
	return clierror.ExitCode(err)
}

func renderError(err error) string {
	// An interrupted command ends the pending line instead of reporting a failure the user already knows about.
	if clierror.ExitCode(err) == clierror.ExitInterrupted {
		return "\n"
	}
	return clierror.Render(err)
}
