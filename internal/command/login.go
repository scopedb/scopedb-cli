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
	"time"

	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/scopedb/scopedb-cli/internal/oauth"
	"github.com/spf13/cobra"
)

const (
	// authorizationRequestTTL matches the server's authorization-request lifetime, so the CLI waits
	// exactly as long as the browser request can still be approved.
	authorizationRequestTTL = 10 * time.Minute

	devicePollInterval = 5 * time.Second
	deviceSlowDownStep = 5 * time.Second
	deviceMaxBackoff   = 30 * time.Second
)

func (a *app) newLoginCommand() *cobra.Command {
	var device bool
	var insecureStorage bool
	var format string
	command := &cobra.Command{
		Use:   "login",
		Short: "Log in through the browser",
		Long: "Log in by approving a Scope CLI request in the ScopeDB Console.\n" +
			"The default flow opens a browser and receives the authorization on a loopback address.\n" +
			"Use --device on a machine without a browser, such as an SSH session, to approve the login from another device.",
		Args: cobra.NoArgs,
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
			if !device {
				if reason := a.browserlessReason(); reason != "" {
					return clierror.WithHint(
						clierror.New(clierror.ExitUsage, "cannot open a browser: "+reason),
						"rerun with 'scope auth login --device' and approve the login from another device",
					)
				}
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
			client, err := runtime.oauthClient(cmd.Context())
			if err != nil {
				var controlErr *controlplane.Error
				if errors.As(err, &controlErr) && controlErr.Status == http.StatusNotFound {
					return clierror.WithHint(
						clierror.New(clierror.ExitUsage, "this ScopeDB deployment does not offer CLI login yet"),
						"ask your administrator to enable it, or set SCOPEDB_ENDPOINT and SCOPEDB_API_KEY for non-interactive access",
					)
				}
				return NormalizeError(err)
			}

			var tokens controlplane.TokenSet
			if device {
				tokens, err = a.deviceLogin(cmd.Context(), client)
			} else {
				tokens, err = a.loopbackLogin(cmd.Context(), client)
			}
			if err != nil {
				return NormalizeError(err)
			}
			if err := runtime.persistLogin(tokens); err != nil {
				return err
			}

			email := a.loginAccountEmail(cmd.Context(), runtime, tokens.AccessToken)
			if format == structuredFormatJSON {
				return writeJSON(a.out, loginResult{Email: email})
			}
			if email != "" {
				_, err = fmt.Fprintf(a.out, "Logged in as %s.\n", email)
			} else {
				_, err = fmt.Fprintln(a.out, "Logged in.")
			}
			return NormalizeError(err)
		},
	}
	command.Flags().BoolVar(&device, "device", false, "log in with a user code on another device instead of a loopback browser redirect")
	command.Flags().BoolVar(&insecureStorage, "insecure-storage", false, "store credentials unencrypted in a 0600 file")
	command.Flags().StringVar(&format, "format", structuredFormatText, "output format: text or json")
	return command
}

type loginResult struct {
	Email string `json:"email,omitempty"`
}

// loopbackLogin runs Authorization Code with PKCE against a loopback redirect.
func (a *app) loopbackLogin(ctx context.Context, client *controlplane.OAuth) (controlplane.TokenSet, error) {
	pkce, err := oauth.NewPKCE()
	if err != nil {
		return controlplane.TokenSet{}, err
	}
	state, err := oauth.NewState()
	if err != nil {
		return controlplane.TokenSet{}, err
	}
	listener, err := oauth.NewLoopback()
	if err != nil {
		return controlplane.TokenSet{}, err
	}
	defer func() { _ = listener.Close() }()

	target := client.AuthorizationURL(state, pkce.Challenge, listener.RedirectURI())
	if _, err := fmt.Fprintf(a.errOut, "Open this URL to approve the login:\n%s\n", target); err != nil {
		return controlplane.TokenSet{}, err
	}
	if err := a.openURL(target); err != nil {
		if _, writeErr := fmt.Fprintf(a.errOut, "Could not open a browser: %s\n", err); writeErr != nil {
			return controlplane.TokenSet{}, writeErr
		}
	}

	waitCtx, cancel := context.WithTimeout(ctx, authorizationRequestTTL)
	defer cancel()
	callback, err := listener.Wait(waitCtx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return controlplane.TokenSet{}, clierror.WithHint(
				clierror.New(clierror.ExitTemporary, "the login was not approved in time"), "run 'scope auth login' to try again")
		}
		return controlplane.TokenSet{}, err
	}
	if callback.Error != "" {
		return controlplane.TokenSet{}, clierror.New(clierror.ExitAuth, describeAuthorizationError(callback))
	}
	if callback.State != state {
		return controlplane.TokenSet{}, errors.New("the login response did not belong to this request; no credentials were saved")
	}
	if callback.Issuer != client.Issuer() {
		return controlplane.TokenSet{}, fmt.Errorf("the login response came from %q, but this CLI is configured for %q; no credentials were saved", callback.Issuer, client.Issuer())
	}
	return client.ExchangeAuthorizationCode(ctx, callback.Code, listener.RedirectURI(), pkce.Verifier)
}

// deviceLogin runs RFC 8628 Device Authorization. It is the only flow that works without a browser
// on the machine running the CLI.
func (a *app) deviceLogin(ctx context.Context, client *controlplane.OAuth) (controlplane.TokenSet, error) {
	device, err := client.StartDeviceAuthorization(ctx)
	if err != nil {
		return controlplane.TokenSet{}, err
	}
	if device.DeviceCode == "" || device.UserCode == "" || device.VerificationURI == "" {
		return controlplane.TokenSet{}, errors.New("ScopeDB returned an incomplete device authorization")
	}
	if _, err := fmt.Fprintf(a.errOut, "To approve this login, open %s and enter the code:\n\n    %s\n\n", device.VerificationURI, device.UserCode); err != nil {
		return controlplane.TokenSet{}, err
	}
	if device.VerificationURIComplete != "" {
		if err := a.openURL(device.VerificationURIComplete); err != nil {
			if _, writeErr := fmt.Fprintf(a.errOut, "Could not open a browser: %s\n", err); writeErr != nil {
				return controlplane.TokenSet{}, writeErr
			}
		}
	}

	interval := time.Duration(device.Interval) * time.Second
	if interval <= 0 {
		interval = devicePollInterval
	}
	deadline := a.now().Add(time.Duration(device.ExpiresIn) * time.Second)
	backoff := interval
	for {
		tokens, err := client.PollDeviceAuthorization(ctx, device.DeviceCode)
		if err == nil {
			return tokens, nil
		}
		if ctx.Err() != nil {
			return controlplane.TokenSet{}, ctx.Err()
		}
		var protocol *controlplane.OAuthError
		if !errors.As(err, &protocol) {
			return controlplane.TokenSet{}, err
		}
		switch protocol.Code {
		case "authorization_pending":
			backoff = interval
		case "slow_down":
			// The server raises the interval permanently for this authorization.
			interval += deviceSlowDownStep
			backoff = interval
		case "access_denied":
			return controlplane.TokenSet{}, clierror.New(clierror.ExitAuth, "the login request was denied in the console")
		case "expired_token":
			return controlplane.TokenSet{}, clierror.WithHint(
				clierror.New(clierror.ExitAuth, "the login request expired"), "run 'scope auth login --device' to start a new one")
		case "invalid_grant":
			return controlplane.TokenSet{}, clierror.WithHint(
				clierror.New(clierror.ExitAuth, "the login request can no longer be redeemed"), "run 'scope auth login --device' to start a new one")
		default:
			if protocol.Status != 0 {
				return controlplane.TokenSet{}, err
			}
			// A transport failure may mean the response was lost, so keep polling with backoff.
			backoff *= 2
			if backoff > deviceMaxBackoff {
				backoff = deviceMaxBackoff
			}
		}
		if !a.now().Before(deadline) {
			return controlplane.TokenSet{}, clierror.WithHint(
				clierror.New(clierror.ExitAuth, "the login request expired"), "run 'scope auth login --device' to start a new one")
		}
		if ctx.Err() != nil {
			return controlplane.TokenSet{}, ctx.Err()
		}
		a.sleep(backoff)
	}
}

// loginAccountEmail reports the account the new login belongs to. A failed lookup must not undo a
// login that is already stored.
func (a *app) loginAccountEmail(ctx context.Context, runtime *runtimeContext, token string) string {
	lookupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	user, err := runtime.control.GetUser(lookupCtx, token)
	if err != nil {
		if _, writeErr := fmt.Fprintln(a.errOut, "Could not check account status. Run 'scope auth status' to retry."); writeErr != nil {
			return ""
		}
		return ""
	}
	account := auth.Account{User: user, Workspaces: []controlplane.Workspace{}}
	if err := a.writeWorkspaceSetup(account); err != nil {
		return ""
	}
	return user.Email
}

func describeAuthorizationError(callback oauth.Callback) string {
	switch callback.Error {
	case "access_denied":
		return "the login request was denied in the console"
	case "":
		return "the login request failed"
	default:
		if callback.ErrorDescription != "" {
			return callback.Error + ": " + callback.ErrorDescription
		}
		return callback.Error
	}
}

// browserlessReason names the environment that makes a loopback redirect unusable, if any. The
// device flow is never selected automatically; the user must ask for it.
func (a *app) browserlessReason() string {
	if a.getenv("SSH_CONNECTION") != "" || a.getenv("SSH_TTY") != "" || a.getenv("SSH_CLIENT") != "" {
		return "this is an SSH session"
	}
	if a.getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "this looks like a Kubernetes container"
	}
	if a.getenv("container") != "" {
		return "this looks like a container"
	}
	return ""
}

func (r *runtimeContext) persistLogin(tokens controlplane.TokenSet) error {
	previous, previousErr := r.credentials.Load(r.config.ControlURL)
	previousFound := previousErr == nil
	if previousErr != nil && !errors.Is(previousErr, credential.ErrNotFound) && !errors.Is(previousErr, credential.ErrInvalidState) {
		r.revokeIssuedLogin(tokens)
		return clierror.Wrap(clierror.ExitGeneral, "login succeeded, but existing credentials could not be read", previousErr)
	}

	var result *clierror.Error
	if err := r.auth.SaveLogin(tokens); err != nil {
		result = clierror.Wrap(clierror.ExitGeneral, "login succeeded, but credentials could not be stored", err)
		if r.config.CredentialStore == config.CredentialStoreKeyring {
			result.Hint = "fix OS keyring access or rerun with 'scope auth login --insecure-storage'"
		}
	} else if err := config.Save(r.paths, r.config); err != nil {
		result = clierror.WithHint(clierror.Wrap(clierror.ExitGeneral, "login succeeded, but configuration could not be stored", err), "check config directory access and retry")
	} else {
		return nil
	}

	rollbackErr := restoreCredentials(r.credentials, r.config.ControlURL, previous, previousFound)
	r.revokeIssuedLogin(tokens)
	if rollbackErr != nil {
		result.Message += " and previous credentials could not be restored"
		result.Err = errors.Join(result.Err, rollbackErr)
		result.Hint = "check config and credential store access before retrying"
	}
	return result
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

// revokeIssuedLogin undoes a login the CLI could not store, so a failed login never leaves a live
// grant behind.
func (r *runtimeContext) revokeIssuedLogin(tokens controlplane.TokenSet) {
	token := tokens.RefreshToken
	if token == "" {
		token = tokens.AccessToken
	}
	if token == "" {
		return
	}
	revokeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := r.oauthClient(revokeCtx)
	if err != nil {
		return
	}
	_ = client.RevokeToken(revokeCtx, token)
}

func (a *app) newLogoutCommand() *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "logout",
		Short: "Revoke the current login and remove local credentials",
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

			err = runtime.auth.Logout(cmd.Context())
			if errors.Is(err, auth.ErrNotLoggedIn) {
				if format == structuredFormatJSON {
					return writeJSON(a.out, logoutResult{Changed: false})
				}
				_, writeErr := fmt.Fprintln(a.out, "Not logged in.")
				return NormalizeError(writeErr)
			}
			var cleanup *auth.LogoutCleanupError
			if errors.As(err, &cleanup) {
				result := NormalizeError(cleanup.Err)
				var cliErr *clierror.Error
				if errors.As(result, &cliErr) {
					cliErr.Message = cleanup.Error()
					cliErr.Hint = "the login stays valid until it expires or is revoked in the Console"
				}
				return result
			}
			if err != nil {
				return NormalizeError(err)
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, logoutResult{Changed: true})
			}
			_, writeErr := fmt.Fprintln(a.out, "Logged out.")
			return NormalizeError(writeErr)
		},
	}
	command.Flags().StringVar(&format, "format", structuredFormatText, "output format: text or json")
	return command
}

type logoutResult struct {
	Changed bool `json:"changed"`
}
