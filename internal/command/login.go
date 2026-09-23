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
	var format string
	command := &cobra.Command{
		Use:   "login",
		Short: "Log in with an email verification code",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateTextFormat(format); err != nil {
				return err
			}
			paths, cfg, err := a.loadConfig(cmd)
			if err != nil {
				return NormalizeError(err)
			}
			if insecureStorage {
				cfg.CredentialStore = config.CredentialStorePlaintext
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
				code, err = a.readVerificationCode(cmd.Context())
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
			previous, previousErr := runtime.credentials.Load(cfg.ControlURL)
			previousFound := previousErr == nil
			if previousErr != nil && !errors.Is(previousErr, credential.ErrNotFound) {
				a.revokeIssuedSession(runtime, response.Token)
				return clierror.Wrap(clierror.ExitGeneral, "login succeeded, but existing credentials could not be read", previousErr)
			}
			if err := runtime.auth.SaveLogin(response); err != nil {
				rollbackErr := restoreCredentials(runtime.credentials, cfg.ControlURL, previous, previousFound)
				a.revokeIssuedSession(runtime, response.Token)
				if rollbackErr != nil {
					return clierror.WithHint(clierror.Wrap(clierror.ExitGeneral, "login succeeded, but credentials could not be stored or restored", errors.Join(err, rollbackErr)), "check credential store access before retrying")
				}
				result := clierror.Wrap(clierror.ExitGeneral, "login succeeded, but credentials could not be stored", err)
				if cfg.CredentialStore == config.CredentialStoreKeyring {
					result.Hint = "fix OS keyring access or rerun with 'scope login --insecure-storage'"
				}
				return result
			}
			// Commit the selected endpoint and storage only after authentication.
			if err := config.Save(paths, cfg); err != nil {
				rollbackErr := restoreCredentials(runtime.credentials, cfg.ControlURL, previous, previousFound)
				a.revokeIssuedSession(runtime, response.Token)
				if rollbackErr != nil {
					return clierror.WithHint(clierror.Wrap(clierror.ExitGeneral, "login succeeded, but configuration could not be stored and previous credentials could not be restored", errors.Join(err, rollbackErr)), "check config and credential store access before retrying")
				}
				return clierror.WithHint(clierror.Wrap(clierror.ExitGeneral, "login succeeded, but configuration could not be stored", err), "check config directory access and retry")
			}
			if response.WorkspaceID == "" {
				session, sessionErr := runtime.control.GetSession(cmd.Context(), response.Token)
				if sessionErr != nil {
					if errors.Is(sessionErr, context.Canceled) {
						return NormalizeError(sessionErr)
					}
					// The session is already saved; a failed status lookup must not undo login.
					if _, err := fmt.Fprintln(a.errOut, "Could not check account status. Run 'scope status' to retry."); err != nil {
						return NormalizeError(err)
					}
				} else if err := a.writeWorkspaceSetup(session); err != nil {
					return err
				}
			}
			if format == structuredFormatJSON {
				result := loginResult{Email: email}
				if response.WorkspaceID != "" {
					result.WorkspaceID = &response.WorkspaceID
				}
				return writeJSON(a.out, result)
			}
			if response.WorkspaceID != "" {
				_, err = fmt.Fprintf(a.out, "Logged in as %s. Current workspace: %s\n", email, response.WorkspaceID)
			} else {
				_, err = fmt.Fprintf(a.out, "Logged in as %s.\n", email)
			}
			return NormalizeError(err)
		},
	}
	command.Flags().StringVar(&email, "email", "", "email address")
	command.Flags().StringVar(&code, "code", "", "verification code (visible in process arguments; prefer stdin)")
	command.Flags().BoolVar(&insecureStorage, "insecure-storage", false, "store credentials unencrypted in a 0600 file")
	command.Flags().StringVarP(&format, "format", "f", structuredFormatText, "output format: text or json")
	return command
}

type loginResult struct {
	Email       string  `json:"email"`
	WorkspaceID *string `json:"workspace_id"`
}

func restoreCredentials(store credential.Store, controlURL string, previous credential.State, found bool) error {
	if found {
		return store.Save(controlURL, previous)
	}
	if err := store.Delete(controlURL); err != nil && !errors.Is(err, credential.ErrNotFound) {
		return err
	}
	return nil
}

func (a *app) revokeIssuedSession(runtime *runtimeContext, token string) {
	if token == "" {
		return
	}
	revokeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = runtime.control.DeleteSession(revokeCtx, token)
}

func (a *app) newLogoutCommand() *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "logout",
		Short: "Revoke the current session and remove local credentials",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateTextFormat(format); err != nil {
				return err
			}
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
				if format == structuredFormatJSON {
					return writeJSON(a.out, logoutResult{LoggedOut: false})
				}
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
			if format == structuredFormatJSON {
				return writeJSON(a.out, logoutResult{LoggedOut: true})
			}
			_, err = fmt.Fprintln(a.out, "Logged out.")
			return NormalizeError(err)
		},
	}
	command.Flags().StringVarP(&format, "format", "f", structuredFormatText, "output format: text or json")
	return command
}

type logoutResult struct {
	LoggedOut bool `json:"logged_out"`
}

func isMissingRemoteSession(err error) bool {
	var controlErr *controlplane.Error
	return errors.As(err, &controlErr) && (controlErr.Status == http.StatusUnauthorized || controlErr.Status == http.StatusNotFound)
}
