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
	"github.com/scopedb/scopedb-cli/internal/controlplane"
)

func workspaceSetupError(err error) *clierror.Error {
	switch {
	case errors.Is(err, auth.ErrApprovalRequired):
		return clierror.WithHint(clierror.Wrap(clierror.ExitAuth, fmt.Sprint(err), err), "run 'scope open' to check approval status in the Console")
	case errors.Is(err, auth.ErrNoWorkspaces):
		return clierror.WithHint(clierror.Wrap(clierror.ExitUsage, fmt.Sprint(err), err), "run 'scope open' to create your first workspace, then 'scope workspace list' and 'scope workspace use <id-or-name>'")
	case errors.Is(err, auth.ErrNoWorkspaceSelected):
		return clierror.WithHint(clierror.Wrap(clierror.ExitUsage, fmt.Sprint(err), err), "run 'scope workspace list' and 'scope workspace use <id-or-name>'")
	default:
		return nil
	}
}

func (a *app) writeWorkspaceSetup(session controlplane.Session) error {
	if err := workspaceSetupError(auth.RequireWorkspace(session)); err != nil {
		_, writeErr := fmt.Fprintf(a.errOut, "%s; %s.\n", err.Message, err.Hint)
		return NormalizeError(writeErr)
	}
	return nil
}
