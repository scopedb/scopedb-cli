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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	scopedb "github.com/scopedb/goscopedb"
	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/scopedb/scopedb-cli/internal/dataplane"
	"github.com/scopedb/scopedb-cli/internal/version"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type credentialFactory func(string, config.Paths, string) (credential.Store, error)

// Dependencies configures the process boundaries used by the command tree.
type Dependencies struct {
	In              io.Reader
	Out             io.Writer
	ErrOut          io.Writer
	HTTPClient      *http.Client
	CredentialStore credentialFactory
	IsInputTerminal func() bool
	IsErrorTerminal func() bool
	OpenURL         func(string) error
	Now             func() time.Time
	Sleep           func(time.Duration)
	Getenv          func(string) string
}

type app struct {
	explicitConnection bool
	machineMode        bool
	in                 io.Reader
	input              *bufio.Reader
	out                io.Writer
	errOut             io.Writer
	httpClient         *http.Client
	query              *dataplane.QueryService
	credentialFactory  credentialFactory
	isInputTerminal    func() bool
	isErrorTerminal    func() bool
	openURL            func(string) error
	now                func() time.Time
	sleep              func(time.Duration)
	getenv             func(string) string
	controlURLFlag     string
	consoleURLFlag     string
	connectionFlag     string
	workspaceFlag      string
	resolvedConnection string
}

type runtimeContext struct {
	paths       config.Paths
	config      config.Config
	control     *controlplane.Client
	credentials *credential.Stores
	auth        *auth.Manager

	oauth *controlplane.OAuth
}

func (r *runtimeContext) oauthClient(ctx context.Context) (*controlplane.OAuth, error) {
	if r.oauth != nil {
		return r.oauth, nil
	}
	client, err := r.control.DiscoverOAuth(ctx)
	if err != nil {
		return nil, err
	}
	r.oauth = client
	return client, nil
}

func (r *runtimeContext) RefreshToken(ctx context.Context, refreshToken string) (controlplane.TokenSet, error) {
	client, err := r.oauthClient(ctx)
	if err != nil {
		return controlplane.TokenSet{}, err
	}
	return client.RefreshToken(ctx, refreshToken)
}

func (r *runtimeContext) RevokeToken(ctx context.Context, token string) error {
	client, err := r.oauthClient(ctx)
	if err != nil {
		return err
	}
	return client.RevokeToken(ctx, token)
}

func newApp(deps Dependencies) *app {
	if deps.In == nil {
		deps.In = os.Stdin
	}
	if deps.Out == nil {
		deps.Out = os.Stdout
	}
	if deps.ErrOut == nil {
		deps.ErrOut = os.Stderr
	}
	if deps.CredentialStore == nil {
		deps.CredentialStore = credential.New
	}
	if deps.IsInputTerminal == nil {
		deps.IsInputTerminal = func() bool { return isTerminal(deps.In) }
	}
	if deps.IsErrorTerminal == nil {
		deps.IsErrorTerminal = func() bool { return isTerminal(deps.ErrOut) }
	}
	if deps.Getenv == nil {
		deps.Getenv = os.Getenv
	}
	if deps.OpenURL == nil {
		deps.OpenURL = func(target string) error { return openURL(target, deps.Getenv) }
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Sleep == nil {
		deps.Sleep = time.Sleep
	}
	return &app{
		in:                deps.In,
		input:             bufio.NewReader(deps.In),
		out:               deps.Out,
		errOut:            deps.ErrOut,
		httpClient:        deps.HTTPClient,
		query:             &dataplane.QueryService{HTTPClient: deps.HTTPClient},
		credentialFactory: deps.CredentialStore,
		isInputTerminal:   deps.IsInputTerminal,
		isErrorTerminal:   deps.IsErrorTerminal,
		openURL:           deps.OpenURL,
		now:               deps.Now,
		sleep:             deps.Sleep,
		getenv:            deps.Getenv,
	}
}

func (a *app) loadConfig(cmd *cobra.Command) (config.Paths, config.Config, error) {
	explicit := cmd.Root().PersistentFlags().Changed("connection") || strings.TrimSpace(a.getenv("SCOPEDB_CONNECTION")) != ""
	a.explicitConnection = explicit
	a.machineMode = !explicit && (strings.TrimSpace(a.getenv("SCOPEDB_ENDPOINT")) != "" || strings.TrimSpace(a.getenv("SCOPEDB_API_KEY")) != "")
	paths, err := config.ResolvePaths()
	if err != nil {
		return config.Paths{}, config.Config{}, err
	}
	if a.machineMode {
		return paths, config.Config{ControlURL: config.DefaultControlURL, ConsoleURL: config.DefaultConsoleURL,
			Temporary: true, SelectedConnection: config.Connection{AuthType: config.AuthAPIKey}}, nil
	}
	// Migrate the old default before creating a named connection, so changing the
	// requested name cannot transfer an existing grant to that new environment.
	saved, err := config.Read(paths)
	if err != nil {
		return config.Paths{}, config.Config{}, err
	}
	if len(saved.Connections) == 0 && !a.machineMode && cmd.CommandPath() != "scope console" {
		legacy, err := config.Load(paths, config.Overrides{})
		if err != nil {
			return config.Paths{}, config.Config{}, err
		}
		if _, err := a.newRuntime(cmd.Context(), paths, legacy); err != nil {
			if cmd.Name() == "login" {
				return config.Paths{}, config.Config{}, clierror.Wrap(clierror.ExitGeneral, "existing credentials could not be read", err)
			}
			return config.Paths{}, config.Config{}, err
		}
	}
	overrides := config.Overrides{Connection: strings.TrimSpace(a.getenv("SCOPEDB_CONNECTION")), AllowCreate: cmd.Name() == "login"}
	if cmd.Root().PersistentFlags().Changed("connection") {
		if err := config.ValidateConnectionName(a.connectionFlag); err != nil {
			return config.Paths{}, config.Config{}, usageError(err.Error())
		}
		overrides.Connection = a.connectionFlag
	}
	flags := cmd.Root().PersistentFlags()
	if flags.Changed("control-url") {
		overrides.ControlURL = a.controlURLFlag
	}
	if flags.Changed("console-url") {
		overrides.ConsoleURL = a.consoleURLFlag
	}
	cfg, err := config.Load(paths, overrides)
	if err != nil {
		return config.Paths{}, config.Config{}, err
	}
	a.resolvedConnection = cfg.ConnectionName
	return paths, cfg, nil
}

func (a *app) newRuntime(ctx context.Context, paths config.Paths, cfg config.Config) (*runtimeContext, error) {
	build := version.Current()
	control, err := controlplane.NewClient(cfg.ControlURL, "scope/"+build.Version, a.httpClient)
	if err != nil {
		return nil, err
	}
	keyring, err := a.credentialFactory(credential.SourceKeyring, paths, config.CredentialReference(paths, cfg.ConnectionName))
	if err != nil {
		return nil, err
	}
	plaintext, err := a.credentialFactory(credential.SourcePlaintext, paths, config.CredentialReference(paths, cfg.ConnectionName))
	if err != nil {
		return nil, err
	}
	credentials := &credential.Stores{
		Keyring:   keyring,
		Plaintext: plaintext,
		OnPlaintext: func(fallback, cleanup error) {
			if fallback != nil {
				_, _ = fmt.Fprintln(a.errOut, "Warning: OS keyring storage failed; falling back to plaintext storage.")
			}
			_, _ = fmt.Fprintf(a.errOut, "Warning: credentials are stored unencrypted in %s.\n", paths.CredentialsFile)
			if cleanup != nil {
				_, _ = fmt.Fprintln(a.errOut, "Warning: OS keyring cleanup could not be verified. Restore keyring access before removing stale credentials.")
			}
		},
	}
	runtime := &runtimeContext{
		paths:       paths,
		config:      cfg,
		control:     control,
		credentials: credentials,
	}
	if !cfg.ConnectionExists && !a.machineMode {
		if err := a.migrateConnection(ctx, runtime); err != nil {
			return nil, err
		}
	}
	runtime.auth = &auth.Manager{
		ConnectionName:    runtime.config.ConnectionName,
		Connection:        &runtime.config.SelectedConnection,
		Paths:             paths,
		Temporary:         cfg.Temporary,
		ConnectionExisted: runtime.config.ConnectionExists,
		ControlURL:        cfg.ControlURL,
		Control:           control,
		OAuth:             runtime,
		Credentials:       credentials,
		LockFile:          paths.LockFile,
		Now:               a.now,
		Sleep:             a.sleep,
		Getenv:            a.getenv,
	}
	return runtime, nil
}

func (a *app) runtime(cmd *cobra.Command) (*runtimeContext, error) {
	paths, cfg, err := a.loadConfig(cmd)
	if err != nil {
		return nil, err
	}
	runtime, err := a.newRuntime(cmd.Context(), paths, cfg)
	if err != nil {
		return nil, err
	}
	runtime.auth.WorkspaceOverride = a.workspaceFlag
	if a.workspaceFlag != "" && runtime.config.SelectedConnection.AuthType == config.AuthAPIKey {
		return nil, usageError("--workspace requires an OAuth connection; API key connections have a fixed endpoint")
	}
	if !usesDataCredentials(cmd) {
		if err := runtime.auth.RequireOAuth(); err != nil {
			return nil, err
		}
	}
	return runtime, nil
}

func usesDataCredentials(cmd *cobra.Command) bool {
	switch cmd.CommandPath() {
	case "scope auth status", "scope doctor", "scope query":
		return true
	}
	return strings.HasPrefix(cmd.CommandPath(), "scope catalog ")
}

// A zero timeout preserves parent cancellation without adding a deadline.
func timeoutContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func (a *app) readLine(ctx context.Context, prompt string) (string, error) {
	if prompt != "" {
		if _, err := fmt.Fprint(a.errOut, prompt); err != nil {
			return "", err
		}
	}
	value, err := readInput(ctx, func() (string, error) { return a.input.ReadString('\n') })
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

// readInput lets a command stop waiting without closing the caller's reader.
// The underlying read may remain blocked until the caller closes it or the process exits.
func readInput(ctx context.Context, read func() (string, error)) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	type input struct {
		value string
		err   error
	}
	done := make(chan input, 1)
	go func() {
		value, err := read()
		done <- input{value: value, err: err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-done:
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return result.value, result.err
	}
}

func isTerminal(stream any) bool {
	file, ok := stream.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}

func openURL(target string, getenv func(string) string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		if getenv("DISPLAY") == "" && getenv("WAYLAND_DISPLAY") == "" {
			return errors.New("no graphical display is available")
		}
		command = exec.Command("xdg-open", target)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("open browser: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	// Some launchers stay alive with the browser. Observe startup failures without
	// waiting for the user to close it; a successful start cannot prove the page loaded.
	select {
	case err := <-exited:
		if err != nil {
			return fmt.Errorf("open browser: %w", err)
		}
		return nil
	case <-time.After(3 * time.Second):
		return nil
	}
}

const keyringAccessHint = "restore OS keyring access; for queries without a keyring, set both SCOPEDB_ENDPOINT and SCOPEDB_API_KEY; " +
	"or explicitly use 'scope auth login --insecure-storage' to store login credentials unencrypted in a 0600 file " +
	"(add --use-device-code --no-browser on headless hosts)"

type connectionError struct {
	name string
	err  error
}

func (e *connectionError) Error() string { return e.err.Error() }
func (e *connectionError) Unwrap() error { return e.err }

// Keep follow-up commands on the same connection, particularly logout instructions.
func (a *app) bindConnectionErrors(cmd *cobra.Command) {
	for _, child := range cmd.Commands() {
		a.bindConnectionErrors(child)
	}
	if run := cmd.RunE; run != nil {
		cmd.RunE = func(command *cobra.Command, args []string) error {
			err := run(command, args)
			if err == nil || a.resolvedConnection == "" {
				return err
			}
			if a.resolvedConnection == "default" && !command.Root().PersistentFlags().Changed("connection") && a.getenv("SCOPEDB_CONNECTION") == "" {
				return err
			}
			return &connectionError{name: a.resolvedConnection, err: err}
		}
	}
}

// NormalizeError maps domain and HTTP errors to the public CLI exit contract.
func NormalizeError(err error) error {
	if err == nil {
		return nil
	}
	var scoped *connectionError
	if errors.As(err, &scoped) {
		normalized := NormalizeError(scoped.err)
		var failure *clierror.Error
		if errors.As(normalized, &failure) {
			copy := *failure
			parts := strings.Split(copy.Hint, "'")
			for i := 1; i < len(parts); i += 2 {
				if strings.HasPrefix(parts[i], "scope ") && !strings.Contains(parts[i], "--connection") {
					parts[i] = "scope --connection " + scoped.name + strings.TrimPrefix(parts[i], "scope")
				}
			}
			copy.Hint = strings.Join(parts, "'")
			if errors.Is(scoped.err, auth.ErrNotLoggedIn) {
				copy.Message = fmt.Sprintf("not logged in to connection %q", scoped.name)
			}
			return &copy
		}
		return normalized
	}
	if errors.Is(err, auth.ErrOAuthRequired) {
		return clierror.WithHint(clierror.Wrap(clierror.ExitUsage, err.Error(), err), "select an OAuth connection with --connection; use connection remove to forget an API key connection")
	}
	if errors.Is(err, config.ErrUnknownConnection) {
		return clierror.WithHint(clierror.Wrap(clierror.ExitUsage, err.Error(), err), "run 'scope connection list' or create the connection with 'scope auth login --connection <name>'")
	}
	var cleanup *auth.LogoutCleanupError
	if errors.As(err, &cleanup) {
		result := NormalizeError(cleanup.Err)
		var failure *clierror.Error
		if errors.As(result, &failure) {
			failure.Message = cleanup.Error()
			failure.Hint = "the login stays valid until it expires or is revoked in the Console"
		}
		return result
	}
	var migrationKeyring *credential.KeyringError
	if errors.Is(err, errLegacyMigration) && errors.As(err, &migrationKeyring) {
		return clierror.WithHint(clierror.Wrap(clierror.ExitGeneral, "could not check or migrate legacy credentials", err), "restore OS keyring access and retry; for queries without migrating, set both SCOPEDB_ENDPOINT and SCOPEDB_API_KEY")
	}
	var ready *clierror.Error
	var keyringErr *credential.KeyringError
	if errors.As(err, &ready) {
		if errors.As(err, &keyringErr) && !strings.Contains(ready.Hint, keyringAccessHint) {
			if ready.Hint != "" {
				ready.Hint += "; "
			}
			ready.Hint += keyringAccessHint
		}
		return err
	}
	var catalogErr *scopedb.Error
	if errors.As(err, &catalogErr) && catalogErr.Kind == scopedb.ErrorKindCatalogFailed {
		return normalizeCatalogError(catalogErr)
	}
	var interrupted *dataplane.InterruptedError
	if errors.As(err, &interrupted) {
		code := clierror.ExitInterrupted
		if errors.Is(err, context.DeadlineExceeded) {
			code = clierror.ExitTemporary
		}
		result := clierror.Wrap(code, interrupted.Error(), err)
		if interrupted.CancelErr != nil {
			result.Hint = "verify the statement's outcome before retrying; it may have completed or still be running"
			return result
		}
		switch interrupted.CancelResult.Status {
		case scopedb.StatementStatusFinished:
			result.Hint = "use the statement ID to retrieve its result; do not rerun a statement with side effects"
		case scopedb.StatementStatusCancelled, scopedb.StatementStatusFailed:
			// The terminal response already explains the outcome.
		default:
			result.Hint = "verify the statement's outcome before retrying; it may have completed or still be running"
		}
		return result
	}
	if errors.Is(err, context.Canceled) {
		return clierror.Wrap(clierror.ExitInterrupted, err.Error(), err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return clierror.Wrap(clierror.ExitTemporary, "operation timed out", err)
	}
	if errors.As(err, &keyringErr) {
		return clierror.WithHint(clierror.Wrap(clierror.ExitGeneral, err.Error(), err), keyringAccessHint)
	}
	if errors.Is(err, auth.ErrNotLoggedIn) {
		return clierror.WithHint(clierror.Wrap(clierror.ExitAuth, "not logged in", err), "run 'scope auth login'")
	}
	if errors.Is(err, auth.ErrLoginExpired) {
		return clierror.WithHint(clierror.Wrap(clierror.ExitAuth, err.Error(), err), "run 'scope auth login'")
	}
	if errors.Is(err, auth.ErrInvalidMachineEnv) {
		return clierror.Wrap(clierror.ExitUsage, err.Error(), err)
	}
	if setupErr := workspaceSetupError(err); setupErr != nil {
		return setupErr
	}
	var oauthErr *controlplane.OAuthError
	if errors.As(err, &oauthErr) {
		code := clierror.ExitGeneral
		switch {
		case oauthErr.Code == "invalid_grant" || oauthErr.Code == "invalid_client" || oauthErr.Code == "access_denied":
			code = clierror.ExitAuth
		case oauthErr.Code == "invalid_request" || oauthErr.Code == "invalid_scope" || oauthErr.Code == "unsupported_grant_type":
			code = clierror.ExitUsage
		case oauthErr.Retryable:
			code = clierror.ExitTemporary
		}
		result := clierror.Wrap(code, oauthErr.Error(), err)
		result.RequestID = oauthErr.RequestID
		if code == clierror.ExitAuth {
			result.Hint = "run 'scope auth login'"
		} else if oauthErr.RetryAfter > 0 {
			result.Hint = "retry after " + oauthErr.RetryAfter.Round(time.Second).String()
		}
		return result
	}
	var controlErr *controlplane.Error
	if errors.As(err, &controlErr) {
		code := clierror.ExitGeneral
		switch {
		case controlErr.Status == http.StatusUnauthorized || controlErr.Status == http.StatusForbidden:
			code = clierror.ExitAuth
		case controlErr.Status == http.StatusNotFound:
			code = clierror.ExitNotFound
		case controlErr.Retryable:
			code = clierror.ExitTemporary
		}
		result := clierror.Wrap(code, controlErr.Error(), err)
		result.RequestID = controlErr.RequestID
		if code == clierror.ExitAuth {
			result.Hint = "run 'scope auth login' or check the active workspace"
		} else if controlErr.RetryAfter > 0 {
			result.Hint = "retry after " + controlErr.RetryAfter.Round(time.Second).String()
		}
		return result
	}
	var dataErr *scopedb.Error
	if errors.As(err, &dataErr) {
		code := clierror.ExitGeneral
		switch {
		case dataErr.Kind == scopedb.ErrorKindConfigInvalid:
			code = clierror.ExitUsage
		case dataErr.HTTPStatus == http.StatusUnauthorized || dataErr.HTTPStatus == http.StatusForbidden:
			code = clierror.ExitAuth
		case dataErr.HTTPStatus == http.StatusNotFound:
			code = clierror.ExitNotFound
		case dataErr.Retryable:
			code = clierror.ExitTemporary
		}
		result := clierror.Wrap(code, dataErr.Error(), err)
		result.RequestID = dataErr.RequestID
		if dataErr.RetryAfter > 0 {
			result.Hint = "retry after " + dataErr.RetryAfter.Round(time.Second).String()
		}
		return result
	}
	if strings.HasPrefix(err.Error(), "unknown command ") {
		return clierror.Wrap(clierror.ExitUsage, err.Error(), err)
	}
	return clierror.Wrap(clierror.ExitGeneral, err.Error(), err)
}
