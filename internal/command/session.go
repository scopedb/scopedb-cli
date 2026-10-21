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
	"errors"
	"fmt"

	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/clierror"
)

func workspaceSetupError(err error) *clierror.Error {
	switch {
	case errors.Is(err, auth.ErrApprovalRequired):
		return clierror.WithHint(clierror.Wrap(clierror.ExitAuth, fmt.Sprint(err), err), "run 'scope console --open' to check approval status in the Console")
	case errors.Is(err, auth.ErrNoWorkspaces):
		return clierror.WithHint(clierror.Wrap(clierror.ExitUsage, fmt.Sprint(err), err), "open the Console with 'scope console --open' to create your first workspace, then run 'scope workspace list' and 'scope workspace use <id-or-name>'")
	case errors.Is(err, auth.ErrNoWorkspaceSelected):
		return clierror.WithHint(clierror.Wrap(clierror.ExitUsage, fmt.Sprint(err), err), "run 'scope workspace list' and 'scope workspace use <id-or-name>'")
	case errors.Is(err, auth.ErrWorkspaceUnavailable):
		return clierror.WithHint(clierror.Wrap(clierror.ExitUsage, fmt.Sprint(err), err), "run 'scope workspace list' and 'scope workspace use <id-or-name>', or restore it in the Console")
	default:
		return nil
	}
}

func (a *app) writeWorkspaceSetup(account auth.Account) error {
	if err := workspaceSetupError(auth.RequireWorkspace(account)); err != nil {
		_, writeErr := fmt.Fprintf(a.errOut, "%s; %s.\n", err.Message, err.Hint)
		return NormalizeError(writeErr)
	}
	return nil
}
