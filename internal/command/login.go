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
	var insecureStorage bool
	var format string
	var workspace string
	var device bool
	command := &cobra.Command{
		Use:   "login",
		Short: "Log in through the browser",
		Long: "Log in by approving a Scope CLI request in the ScopeDB Console.\n" +
			"The default flow opens a browser and receives the authorization on a loopback address.\n" +
			"Use --device on a machine without a browser, such as an SSH session or a container, to approve a code\n" +
			"from another device; the device flow prints a link and a code and never opens a browser.",
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
						clierror.New(clierror.ExitUsage, "CLI login requires ScopeDB v0.23.0 or newer; this deployment is older"),
						"upgrade the platform, or set SCOPEDB_ENDPOINT and SCOPEDB_API_KEY for non-interactive access",
					)
				}
				return NormalizeError(err)
			}

			tokens, err := a.authorizeLogin(cmd.Context(), client, format, device)
			if err != nil {
				return NormalizeError(loginMenuError(err, false))
			}
			if err := runtime.persistLogin(cmd.Context(), tokens); err != nil {
				return err
			}

			selection, err := a.selectLoginWorkspace(cmd.Context(), runtime, workspace, format)
			if err != nil {
				return NormalizeError(loginMenuError(err, true))
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
	command.Flags().BoolVar(&insecureStorage, "insecure-storage", false, "store credentials unencrypted in a 0600 file")
	command.Flags().BoolVar(&device, "device", false, "approve a device code instead of opening a browser")
	command.Flags().StringVar(&format, "format", structuredFormatText, "output format: text or json")
	command.Flags().StringVar(&workspace, "workspace", "", "select this workspace for the login")
	return command
}

const loginCancelled = "login cancelled; no credentials were saved"

func (a *app) isInteractive() bool {
	return a.isInputTerminal != nil && a.isInputTerminal() && a.isErrorTerminal != nil && a.isErrorTerminal()
}

// loginMenuError turns the menu sentinels into the documented exit codes. A workspace menu runs after
// the login is stored, so its interrupt leaves those credentials in place.
func loginMenuError(err error, credentialsSaved bool) error {
	switch {
	case errors.Is(err, errMenuCancelled):
		if credentialsSaved {
			return clierror.New(clierror.ExitAuth, "login cancelled; the credentials already saved remain")
		}
		return clierror.New(clierror.ExitAuth, loginCancelled)
	case errors.Is(err, errMenuInterrupted):
		if credentialsSaved {
			return clierror.New(clierror.ExitInterrupted, "login interrupted; the credentials already saved remain")
		}
		return clierror.New(clierror.ExitInterrupted, "login interrupted; no credentials were saved")
	default:
		return err
	}
}

func (a *app) authorizeLogin(ctx context.Context, client *controlplane.OAuth, format string, device bool) (controlplane.TokenSet, error) {
	if device {
		return a.deviceLogin(ctx, client)
	}
	if reason := a.browserlessReason(); reason != "" {
		return controlplane.TokenSet{}, clierror.WithHint(
			clierror.New(clierror.ExitUsage, reason+"; browser login cannot reach this machine"),
			"run 'scope auth login --device'",
		)
	}
	if a.canPrompt(format) {
		choice, err := a.chooseMenu("How do you want to sign in?", []menuOption{
			{label: "Sign in with your browser", note: "recommended"},
			{label: "Sign in with a device code"},
		})
		if err != nil {
			return controlplane.TokenSet{}, err
		}
		if choice == 0 {
			return a.loopbackLogin(ctx, client)
		}
		return a.deviceLogin(ctx, client)
	}
	return a.loopbackLogin(ctx, client)
}

type loginResult struct {
	Email      string              `json:"email,omitempty"`
	Workspace  *workspaceListItem  `json:"workspace,omitempty"`
	Workspaces []workspaceListItem `json:"workspaces,omitempty"`
}

type loginSelection struct {
	email      string
	workspace  *controlplane.Workspace
	kept       bool
	candidates []controlplane.Workspace
}

func (s loginSelection) result() loginResult {
	result := loginResult{Email: s.email}
	if s.workspace != nil {
		view := workspaceListItemFor(*s.workspace, true)
		result.Workspace = &view
	}
	if len(s.candidates) > 0 {
		result.Workspaces = workspaceListItems(s.candidates, "")
	}
	return result
}

// selectLoginWorkspace decides which workspace the new login uses. The account lookup stays best
// effort, because a login that is already stored must not fail when only the account check did.
func (a *app) selectLoginWorkspace(ctx context.Context, runtime *runtimeContext, requested, format string) (loginSelection, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	account, err := runtime.auth.Account(lookupCtx)
	if err != nil {
		a.warnAccountUnchecked()
		return loginSelection{}, nil
	}
	if workspace, owned := workspaceByID(account.Workspaces, account.SelectedWorkspaceID); account.SelectedWorkspaceID != "" && (!owned || workspace.ScheduledForDeletion()) {
		if err := runtime.auth.ClearWorkspace(lookupCtx); err != nil {
			return loginSelection{}, err
		}
		account.SelectedWorkspaceID = ""
	}

	selection := loginSelection{email: account.User.Email}
	switch {
	case strings.TrimSpace(requested) != "":
		workspace, err := resolveWorkspace(account.Workspaces, requested)
		if err != nil {
			return loginSelection{}, err
		}
		if workspace.ScheduledForDeletion() {
			return loginSelection{}, clierror.WithHint(
				clierror.New(clierror.ExitUsage, fmt.Sprintf("workspace %s (%s) is scheduled for deletion", workspace.Name(), workspace.ID)),
				"restore it in the Console before selecting it",
			)
		}
		if err := runtime.auth.SelectWorkspace(lookupCtx, workspace.ID); err != nil {
			return loginSelection{}, err
		}
		selection.workspace = &workspace
	case account.SelectedWorkspaceID != "":
		workspace, _ := workspaceByID(account.Workspaces, account.SelectedWorkspaceID)
		selection.workspace = &workspace
		selection.kept = true
	case len(account.Workspaces) == 1:
		workspace := account.Workspaces[0]
		if workspace.ScheduledForDeletion() {
			selection.candidates = account.Workspaces
			break
		}
		if err := runtime.auth.SelectWorkspace(lookupCtx, workspace.ID); err != nil {
			return loginSelection{}, err
		}
		selection.workspace = &workspace
	case len(account.Workspaces) > 1:
		if a.canPrompt(format) {
			picked, err := a.promptLoginWorkspace(lookupCtx, runtime, account)
			if err != nil {
				return loginSelection{}, err
			}
			if picked != nil {
				selection.workspace = picked
				return selection, nil
			}
		} else {
			selection.candidates = account.Workspaces
		}
	}
	if selection.workspace == nil {
		if err := a.writeWorkspaceSetup(account); err != nil {
			return loginSelection{}, err
		}
	}
	return selection, nil
}

func (a *app) promptLoginWorkspace(ctx context.Context, runtime *runtimeContext, account auth.Account) (*controlplane.Workspace, error) {
	workspaces := account.Workspaces
	options := make([]menuOption, 0, len(workspaces)+1)
	for _, workspace := range workspaces {
		options = append(options, menuOption{
			label: fmt.Sprintf("%s (%s, %s)", workspace.Name(), workspace.ID, workspaceStatus(workspace)),
		})
	}
	options = append(options, menuOption{
		label: "Skip for now",
		note:  "select later with 'scope workspace use <id-or-name>'",
	})
	for {
		choice, err := a.chooseMenuWith("Which workspace do you want to use?", options, "skip")
		if err != nil {
			if errors.Is(err, errMenuCancelled) {
				return nil, nil
			}
			if errors.Is(err, errMenuInterrupted) {
				if _, writeErr := fmt.Fprintln(a.errOut, "Login saved; no workspace was selected."); writeErr != nil {
					return nil, writeErr
				}
			}
			return nil, err
		}
		if choice == len(workspaces) {
			return nil, nil
		}
		workspace := workspaces[choice]
		if workspace.ScheduledForDeletion() {
			if _, err := fmt.Fprintf(a.errOut, "Workspace %s is scheduled for deletion; restore it in the Console or choose another.\n", workspace.Name()); err != nil {
				return nil, err
			}
			continue
		}
		if err := runtime.auth.SelectWorkspace(ctx, workspace.ID); err != nil {
			return nil, err
		}
		return &workspace, nil
	}
}

func (a *app) canPrompt(format string) bool {
	return format != structuredFormatJSON && a.isInteractive()
}

func (a *app) renderLoginSelection(selection loginSelection) error {
	if selection.workspace == nil {
		if len(selection.candidates) > 0 {
			writeWorkspaceListTable(a.out, selection.candidates, "")
		}
		return nil
	}
	verb := "Using"
	if selection.kept {
		verb = "Keeping"
	}
	_, err := fmt.Fprintf(a.out, "%s workspace %s (%s).\n", verb, selection.workspace.Name(), selection.workspace.ID)
	return NormalizeError(err)
}

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
		if _, writeErr := fmt.Fprintf(a.errOut, "Could not open a browser (%s); open the URL above to continue.\n", err); writeErr != nil {
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

func (a *app) deviceLogin(ctx context.Context, client *controlplane.OAuth) (controlplane.TokenSet, error) {
	device, err := client.StartDeviceAuthorization(ctx)
	if err != nil {
		return controlplane.TokenSet{}, err
	}
	if device.DeviceCode == "" || device.UserCode == "" || device.VerificationURI == "" || device.ExpiresIn <= 0 {
		return controlplane.TokenSet{}, errors.New("ScopeDB returned an incomplete device authorization")
	}
	if err := a.writeDeviceInstructions(device); err != nil {
		return controlplane.TokenSet{}, err
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
		if errors.Is(saveErr, auth.ErrCredentialsUnreadable) {
			return clierror.Wrap(clierror.ExitGeneral, "login succeeded, but existing credentials could not be read", saveErr)
		}
		result := clierror.Wrap(clierror.ExitGeneral, "login succeeded, but credentials could not be stored", saveErr)
		if r.config.CredentialStore == config.CredentialStoreKeyring {
			result.Hint = "fix OS keyring access or rerun with 'scope auth login --insecure-storage'"
		}
		return result
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

// revokeIssuedLogin undoes a login the CLI could not store, so a failed login never leaves a live grant behind.
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
