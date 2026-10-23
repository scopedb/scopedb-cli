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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
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
	var insecureStorage, noBrowser, useDeviceCode bool
	var format, workspace string
	command := &cobra.Command{
		Use:   "login",
		Short: "Log in through the ScopeDB Console",
		Long: "Log in by approving a Scope CLI request in the ScopeDB Console.\n" +
			"Opens your browser and completes the login through a callback on this device. If the browser\n" +
			"does not open, open the printed URL on the same device. Use --use-device-code to approve\n" +
			"from another device, or --no-browser to skip opening a browser automatically in either flow.\n\n" +
			"Keeps your selected workspace or selects the first available workspace by ID and prints its\n" +
			"name and ID. Use 'scope workspace use <id-or-name>' to switch afterwards.\n" +
			"Login does not require an interactive terminal.\n\n" +
			"Stores credentials in the OS keyring. On Linux this requires a D-Bus session and Secret Service.\n" +
			"If no keyring is available, use --insecure-storage to explicitly allow an unencrypted 0600 file.\n" +
			"For queries without a login, set both SCOPEDB_ENDPOINT and SCOPEDB_API_KEY.",
		Example: "  scope auth login\n  scope auth login --use-device-code --no-browser",
		Args:    cobra.NoArgs,
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
			if _, stored, err := runtime.auth.RenewableLogin(); err != nil {
				return NormalizeError(clierror.Wrap(clierror.ExitGeneral, "existing credentials could not be read", err))
			} else if stored {
				if err := refuseSecondLogin(cmd.Context(), runtime); err != nil {
					return NormalizeError(err)
				}
			}
			client, err := runtime.oauthClient(cmd.Context())
			if err != nil {
				var controlErr *controlplane.Error
				if errors.As(err, &controlErr) && controlErr.Status == http.StatusNotFound {
					return clierror.WithHint(
						clierror.New(clierror.ExitUsage, "CLI login requires ScopeDB v0.23.0 or newer; this deployment is older"),
						"upgrade the platform, or set SCOPEDB_ENDPOINT and SCOPEDB_API_KEY for non-interactive access",
					)
				}
				return NormalizeError(err)
			}

			var tokens controlplane.TokenSet
			if useDeviceCode {
				tokens, err = a.deviceLogin(cmd.Context(), client, !noBrowser)
			} else {
				tokens, err = a.loopbackLogin(cmd.Context(), client, !noBrowser)
			}
			if err != nil {
				return NormalizeError(err)
			}
			if err := runtime.persistLogin(cmd.Context(), tokens); err != nil {
				return NormalizeError(err)
			}

			selection, err := a.selectLoginWorkspace(cmd.Context(), runtime, workspace)
			if err != nil {
				return NormalizeError(err)
			}
			if format == structuredFormatJSON {
				return writeJSON(a.out, selection.result())
			}
			if selection.email != "" {
				_, err = fmt.Fprintf(a.out, "Logged in as %s.\n", selection.email)
			} else {
				_, err = fmt.Fprintln(a.out, "Logged in.")
			}
			if err != nil {
				return NormalizeError(err)
			}
			return a.renderLoginSelection(selection)
		},
	}
	command.Flags().StringVar(&format, "format", structuredFormatText, "output format: text or json")
	command.Flags().StringVar(&workspace, "workspace", "", "select this workspace; defaults to the first available workspace by ID")
	command.Flags().BoolVar(&noBrowser, "no-browser", false, "do not open the browser automatically")
	command.Flags().BoolVar(&useDeviceCode, "use-device-code", false, "use a device code to approve login from any device")
	command.Flags().BoolVar(&insecureStorage, "insecure-storage", false, "store credentials unencrypted in a 0600 file")
	return command
}

// A second login would leave the first grant active in ScopeDB with no local credential left to end it.
func refuseSecondLogin(ctx context.Context, runtime *runtimeContext) error {
	accountCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	account, err := runtime.auth.Account(accountCtx)
	cancel()
	if err == nil {
		return clierror.WithHint(clierror.New(clierror.ExitAuth, "already logged in as "+account.User.Email), "run 'scope auth logout' first")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// A login whose refresh token is rejected can never work again, so a new login replaces it instead of demanding a logout.
	if errors.Is(err, auth.ErrNotLoggedIn) || errors.Is(err, auth.ErrLoginExpired) {
		return nil
	}
	return clierror.WithHint(clierror.New(clierror.ExitAuth, "already logged in"), "run 'scope auth status' to see the account, or 'scope auth logout' to sign out first")
}

type loginSelection struct {
	email     string
	workspace *controlplane.Workspace
	kept      bool
}

type loginResult struct {
	Email     string             `json:"email,omitempty"`
	Workspace *workspaceListItem `json:"workspace,omitempty"`
}

func (s loginSelection) result() loginResult {
	result := loginResult{Email: s.email}
	if s.workspace != nil {
		view := workspaceListItemFor(*s.workspace, true)
		result.Workspace = &view
	}
	return result
}

// selectLoginWorkspace decides which workspace the new login uses. The account lookup stays best
// effort, because a login that is already stored must not fail when only the account check did.
func (a *app) selectLoginWorkspace(ctx context.Context, runtime *runtimeContext, requested string) (loginSelection, error) {
	accountCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	account, err := runtime.auth.Account(accountCtx)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return loginSelection{}, ctx.Err()
		}
		if errors.Is(err, context.Canceled) {
			return loginSelection{}, err
		}
		if strings.TrimSpace(requested) != "" {
			return loginSelection{}, workspaceSelectionError(err, requested)
		}
		a.warnAccountUnchecked()
		return loginSelection{}, nil
	}
	if workspace, owned := workspaceByID(account.Workspaces, account.SelectedWorkspaceID); account.SelectedWorkspaceID != "" && (!owned || workspace.ScheduledForDeletion()) {
		if err := runtime.auth.ClearWorkspace(ctx); err != nil {
			return loginSelection{}, err
		}
		account.SelectedWorkspaceID = ""
	}

	selection := loginSelection{email: account.User.Email}
	switch {
	case strings.TrimSpace(requested) != "":
		workspace, err := resolveWorkspace(account.Workspaces, requested)
		if err != nil {
			return loginSelection{}, workspaceSelectionError(err, requested)
		}
		if workspace.ScheduledForDeletion() {
			return loginSelection{}, workspaceSelectionError(clierror.WithHint(
				clierror.New(clierror.ExitUsage, fmt.Sprintf("workspace %s (%s) is scheduled for deletion", workspace.Name(), workspace.ID)),
				"restore it in the Console before selecting it",
			), requested)
		}
		if err := runtime.auth.SelectWorkspace(ctx, workspace.ID); err != nil {
			return loginSelection{}, workspaceSelectionError(err, requested)
		}
		selection.workspace = &workspace
	case account.SelectedWorkspaceID != "":
		workspace, _ := workspaceByID(account.Workspaces, account.SelectedWorkspaceID)
		selection.workspace = &workspace
		selection.kept = true
	default:
		available := availableWorkspaces(account.Workspaces)
		if len(available) > 0 {
			workspace := available[0]
			if err := runtime.auth.SelectWorkspace(ctx, workspace.ID); err != nil {
				return loginSelection{}, err
			}
			selection.workspace = &workspace
		}
	}
	if selection.workspace == nil {
		if err := a.writeWorkspaceSetup(account); err != nil {
			return loginSelection{}, err
		}
	}
	return selection, nil
}

func workspaceSelectionError(err error, requested string) error {
	result := NormalizeError(err)
	var cliErr *clierror.Error
	if errors.As(result, &cliErr) {
		cliErr.Message = fmt.Sprintf("login saved, but workspace %s was not selected: %s", requested, cliErr.Message)
		cliErr.Hint = fmt.Sprintf("run 'scope workspace use %s'", requested)
	}
	return result
}

func availableWorkspaces(workspaces []controlplane.Workspace) []controlplane.Workspace {
	available := make([]controlplane.Workspace, 0, len(workspaces))
	for _, workspace := range workspaces {
		if !workspace.ScheduledForDeletion() {
			available = append(available, workspace)
		}
	}
	sort.Slice(available, func(i, j int) bool { return available[i].ID < available[j].ID })
	return available
}

func (a *app) renderLoginSelection(selection loginSelection) error {
	if selection.workspace == nil {
		return nil
	}
	verb := "Using"
	if selection.kept {
		verb = "Keeping"
	}
	_, err := fmt.Fprintf(a.out, "%s workspace %s (%s).\n", verb, selection.workspace.Name(), selection.workspace.ID)
	return NormalizeError(err)
}

func (a *app) loopbackLogin(ctx context.Context, client *controlplane.OAuth, openBrowser bool) (controlplane.TokenSet, error) {
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
	if _, err := fmt.Fprintf(a.errOut, "Open this URL to approve the login on this device:\n%s\n\nTo approve from another device, cancel and run 'scope auth login --use-device-code'.\n", target); err != nil {
		return controlplane.TokenSet{}, err
	}
	if openBrowser {
		// Opening the browser is best effort; the printed URL can still complete this flow.
		_ = a.openURL(target)
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
	if callback.State != state {
		return controlplane.TokenSet{}, errors.New("the login response did not belong to this request; no credentials were saved")
	}
	if callback.Issuer != client.Issuer() {
		return controlplane.TokenSet{}, fmt.Errorf("the login response came from %q, but this CLI is configured for %q; no credentials were saved", callback.Issuer, client.Issuer())
	}
	if callback.Error != "" {
		return controlplane.TokenSet{}, clierror.New(clierror.ExitAuth, describeAuthorizationError(callback))
	}
	if callback.Code == "" {
		return controlplane.TokenSet{}, errors.New("the login response did not include an authorization code; no credentials were saved")
	}
	return client.ExchangeAuthorizationCode(ctx, callback.Code, listener.RedirectURI(), pkce.Verifier)
}

func (a *app) deviceLogin(ctx context.Context, client *controlplane.OAuth, openBrowser bool) (controlplane.TokenSet, error) {
	device, err := client.StartDeviceAuthorization(ctx)
	if err != nil {
		return controlplane.TokenSet{}, err
	}
	if err := a.writeDeviceInstructions(device); err != nil {
		return controlplane.TokenSet{}, err
	}
	if openBrowser {
		target := device.VerificationURIComplete
		if target == "" {
			target = device.VerificationURI
		}
		// Keep polling even if the user must open the printed link manually.
		_ = a.openURL(target)
	}
	stopWaiting := a.startAuthorizationWait(time.Duration(device.ExpiresIn) * time.Second)
	defer stopWaiting()

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
				clierror.New(clierror.ExitAuth, "the login request expired"), "run 'scope auth login' to start a new one")
		case "invalid_grant":
			return controlplane.TokenSet{}, clierror.WithHint(
				clierror.New(clierror.ExitAuth, "the login request can no longer be redeemed"), "run 'scope auth login' to start a new one")
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
				clierror.New(clierror.ExitAuth, "the login request expired"), "run 'scope auth login' to start a new one")
		}
		if ctx.Err() != nil {
			return controlplane.TokenSet{}, ctx.Err()
		}
		if err := a.waitForPoll(ctx, backoff); err != nil {
			return controlplane.TokenSet{}, err
		}
	}
}

func (a *app) writeDeviceInstructions(device controlplane.DeviceAuthorization) error {
	if device.VerificationURIComplete == "" {
		_, err := fmt.Fprintf(a.errOut, "To approve this login, open %s and enter the code:\n\n    %s\n\n", device.VerificationURI, device.UserCode)
		return err
	}
	if _, err := fmt.Fprintf(a.errOut, "To approve this login, open:\n\n    %s\n\n", device.VerificationURIComplete); err != nil {
		return err
	}
	_, err := fmt.Fprintf(a.errOut, "Alternatively, open %s and enter the code:\n\n    %s\n\n", device.VerificationURI, device.UserCode)
	return err
}

// waitForPoll waits out one polling interval. The timer is interrupted by the context, so Ctrl+C
// ends a device-code wait instead of being swallowed by a backoff of up to deviceMaxBackoff.
func (a *app) waitForPoll(ctx context.Context, interval time.Duration) error {
	waited := make(chan struct{})
	go func() {
		defer close(waited)
		a.sleep(interval)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-waited:
		return nil
	}
}

func (a *app) startAuthorizationWait(lifetime time.Duration) func() {
	message := fmt.Sprintf("Waiting for authorization... (expires in %s; Ctrl+C to cancel)", describeLifetime(lifetime))
	if !a.isErrorTerminal() {
		_, _ = fmt.Fprintln(a.errOut, message)
		return func() {}
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	frames := []string{"|", "/", "-", "\\"}
	go func() {
		defer close(done)
		defer func() { _, _ = fmt.Fprint(a.errOut, "\r\x1b[K") }()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for index := 0; ; index++ {
			if _, err := fmt.Fprintf(a.errOut, "\r%s %s", frames[index%len(frames)], message); err != nil {
				return
			}
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			close(stop)
			<-done
		})
	}
}

func describeLifetime(lifetime time.Duration) string {
	total := int64(lifetime / time.Second)
	if total <= 0 {
		return "0s"
	}
	hours := total / 3600
	minutes := total % 3600 / 60
	seconds := total % 60
	switch {
	case hours > 0:
		return fmt.Sprintf("%dh%dm", hours, minutes)
	case minutes > 0 && seconds > 0:
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	case minutes > 0:
		return fmt.Sprintf("%dm", minutes)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}

func (a *app) warnAccountUnchecked() {
	_, _ = fmt.Fprintln(a.errOut, "Could not check account status. Run 'scope auth status' to retry.")
}

func describeAuthorizationError(callback oauth.Callback) string {
	if callback.Error == "access_denied" {
		return "the login request was denied in the console"
	}
	return "the login request failed; no credentials were saved"
}

func (r *runtimeContext) persistLogin(ctx context.Context, tokens controlplane.TokenSet) error {
	savedPrevious, savedFound, writtenAccessToken, saveErr := r.auth.SaveLogin(ctx, tokens)
	if saveErr != nil {
		r.revokeIssuedLogin(tokens)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(saveErr, context.Canceled) || errors.Is(saveErr, context.DeadlineExceeded) {
			return saveErr
		}
		if errors.Is(saveErr, auth.ErrAlreadyLoggedIn) {
			return clierror.WithHint(clierror.Wrap(clierror.ExitAuth, "another login completed while authorization was in progress", saveErr), "run 'scope auth status' to inspect it, or 'scope auth logout' before logging in again")
		}
		if errors.Is(saveErr, auth.ErrCredentialsUnreadable) {
			return clierror.Wrap(clierror.ExitGeneral, "login succeeded, but existing credentials could not be read", saveErr)
		}
		return clierror.Wrap(clierror.ExitGeneral, "login succeeded, but credentials could not be stored", saveErr)
	}
	if err := config.Save(r.paths, r.config); err == nil {
		return nil
	} else {
		result := clierror.WithHint(clierror.Wrap(clierror.ExitGeneral, "login succeeded, but configuration could not be stored", err), "check config directory access and retry")
		rollbackErr := r.auth.RestoreLogin(ctx, savedPrevious, savedFound, writtenAccessToken)
		r.revokeIssuedLogin(tokens)
		if rollbackErr != nil {
			result.Message += " and previous credentials could not be restored"
			result.Err = errors.Join(result.Err, rollbackErr)
			result.Hint = "check config and credential store access before retrying"
		}
		return result
	}
}

// revokeIssuedLogin tries to revoke a login the CLI could not store.
// Cleanup failures do not replace the original login error.
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
