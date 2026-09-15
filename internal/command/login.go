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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/spf13/cobra"
)

func (a *app) newLoginCommand() *cobra.Command {
	var email string
	var code string
	var insecureStorage bool
	command := &cobra.Command{
		Use:   "login",
		Short: "Log in with an email verification code",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths, cfg, err := a.loadConfig(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			if insecureStorage {
				cfg.CredentialStore = config.CredentialStorePlaintext
			}
			// Login establishes the active control-plane profile, so persist the
			// resolved non-secret endpoints together with the storage choice.
			if err := config.Save(paths, cfg); err != nil {
				return NormalizeError(err)
			}
			if cfg.CredentialStore == config.CredentialStorePlaintext {
				if _, err := fmt.Fprintln(a.errOut, "Warning: credentials will be stored unencrypted in a permission-restricted file."); err != nil {
					return NormalizeError(err)
				}
			}
			runtime, err := a.newRuntime(paths, cfg)
			if err != nil {
				return NormalizeError(err)
			}

			email = strings.TrimSpace(email)
			if email == "" {
				if !a.isInputTerminal() {
					return usageError("--email is required when input is not interactive")
				}
				email, err = a.readLine(cmd.Context(), "Email: ")
				if err != nil {
					return NormalizeError(err)
				}
			}
			if email == "" {
				return usageError("email must not be empty")
			}

			begin, err := runtime.control.BeginLogin(cmd.Context(), email)
			if err != nil {
				return NormalizeError(err)
			}
			if begin.LoginChallenge == "" {
				return NormalizeError(errors.New("ScopeDB returned an empty login challenge"))
			}
			if _, err := fmt.Fprintln(a.errOut, "A verification code has been sent if this email can sign in."); err != nil {
				return NormalizeError(err)
			}

			code = strings.TrimSpace(code)
			if code == "" {
				prompt := ""
				if a.isInputTerminal() {
					prompt = "Verification code: "
				}
				code, err = a.readLine(cmd.Context(), prompt)
				if err != nil {
					return NormalizeError(err)
				}
			}
			if code == "" {
				return usageError("provide a verification code with --code or stdin")
			}

			response, err := runtime.control.VerifyLogin(cmd.Context(), begin.LoginChallenge, code)
			if err != nil {
				return NormalizeError(err)
			}
			if err := runtime.auth.SaveLogin(response); err != nil {
				revokeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = runtime.control.DeleteSession(revokeCtx, response.Token)
				result := clierror.Wrap(clierror.ExitGeneral, "login succeeded, but credentials could not be stored", err)
				if cfg.CredentialStore == config.CredentialStoreKeyring {
					result.Hint = "fix OS keyring access or rerun with 'scope login --insecure-storage'"
				}
				return result
			}
			if response.WorkspaceID != "" {
				_, err = fmt.Fprintf(a.out, "Logged in as %s. Current workspace: %s\n", email, response.WorkspaceID)
				return NormalizeError(err)
			}
			if _, err := fmt.Fprintf(a.out, "Logged in as %s.\n", email); err != nil {
				return NormalizeError(err)
			}
			session, err := runtime.control.GetSession(cmd.Context(), response.Token)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return NormalizeError(err)
				}
				// The session is already saved; a failed status lookup must not undo login.
				_, writeErr := fmt.Fprintln(a.errOut, "Could not check account status. Run 'scope status' to retry.")
				return NormalizeError(writeErr)
			}
			return a.writeWorkspaceSetup(session)
		},
	}
	command.Flags().StringVar(&email, "email", "", "email address")
	command.Flags().StringVar(&code, "code", "", "verification code (for non-interactive input)")
	command.Flags().BoolVar(&insecureStorage, "insecure-storage", false, "store credentials unencrypted in a 0600 file")
	return command
}

func (a *app) newLogoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke the current session and remove local credentials",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtime, err := a.runtime(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			if _, active, machineErr := runtime.auth.MachineAccess(); machineErr != nil {
				return NormalizeError(machineErr)
			} else if active {
				return clierror.WithHint(clierror.New(clierror.ExitUsage, "environment-provided API keys cannot be logged out"), "unset SCOPEDB_ENDPOINT and SCOPEDB_API_KEY")
			}

			state, err := runtime.credentials.Load(runtime.config.ControlURL)
			if errors.Is(err, credential.ErrNotFound) {
				_, err := fmt.Fprintln(a.out, "Not logged in.")
				return NormalizeError(err)
			}
			if err != nil {
				return NormalizeError(err)
			}
			remoteErr := runtime.control.DeleteSession(cmd.Context(), state.SessionToken)
			localErr := runtime.credentials.Delete(runtime.config.ControlURL)
			if localErr != nil && !errors.Is(localErr, credential.ErrNotFound) {
				return NormalizeError(localErr)
			}
			if remoteErr != nil && !isMissingRemoteSession(remoteErr) {
				result := NormalizeError(remoteErr)
				var cliErr *clierror.Error
				if errors.As(result, &cliErr) {
					cliErr.Message = "local credentials removed, but the remote session could not be revoked: " + remoteErr.Error()
				}
				return result
			}
			_, err = fmt.Fprintln(a.out, "Logged out.")
			return NormalizeError(err)
		},
	}
}

func isMissingRemoteSession(err error) bool {
	var controlErr *controlplane.Error
	return errors.As(err, &controlErr) && (controlErr.Status == http.StatusUnauthorized || controlErr.Status == http.StatusNotFound)
}
