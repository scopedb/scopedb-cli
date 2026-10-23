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
	"sync"
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

type credentialFactory func(string, config.Paths) (credential.Store, error)

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
	in                io.Reader
	input             *bufio.Reader
	out               io.Writer
	errOut            io.Writer
	httpClient        *http.Client
	query             *dataplane.QueryService
	credentialFactory credentialFactory
	isInputTerminal   func() bool
	isErrorTerminal   func() bool
	openURL           func(string) error
	now               func() time.Time
	sleep             func(time.Duration)
	getenv            func(string) string
	controlURLFlag    string
	consoleURLFlag    string
}

type runtimeContext struct {
	paths       config.Paths
	config      config.Config
	control     *controlplane.Client
	credentials credential.Store
	auth        *auth.Manager

	oauthMu sync.Mutex
	oauth   *controlplane.OAuth
}

func (r *runtimeContext) oauthClient(ctx context.Context) (*controlplane.OAuth, error) {
	r.oauthMu.Lock()
	defer r.oauthMu.Unlock()
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

type runtimeOAuth struct {
	runtime *runtimeContext
}

func (o *runtimeOAuth) RefreshToken(ctx context.Context, refreshToken string) (controlplane.TokenSet, error) {
	client, err := o.runtime.oauthClient(ctx)
	if err != nil {
		return controlplane.TokenSet{}, err
	}
	return client.RefreshToken(ctx, refreshToken)
}

func (o *runtimeOAuth) RevokeToken(ctx context.Context, token string) error {
	client, err := o.runtime.oauthClient(ctx)
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
	paths, err := config.ResolvePaths()
	if err != nil {
		return config.Paths{}, config.Config{}, err
	}
	overrides := config.Overrides{}
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
	return paths, cfg, nil
}

func (a *app) newRuntime(paths config.Paths, cfg config.Config) (*runtimeContext, error) {
	build := version.Current()
	control, err := controlplane.NewClient(cfg.ControlURL, "scope/"+build.Version, a.httpClient)
	if err != nil {
		return nil, err
	}
	credentials, err := a.credentialFactory(cfg.CredentialStore, paths)
	if err != nil {
		return nil, err
	}
	runtime := &runtimeContext{
		paths:       paths,
		config:      cfg,
		control:     control,
		credentials: credentials,
	}
	runtime.auth = &auth.Manager{
		ControlURL:  cfg.ControlURL,
		Control:     control,
		OAuth:       &runtimeOAuth{runtime: runtime},
		Credentials: credentials,
		LockFile:    paths.LockFile,
		Now:         a.now,
		Sleep:       a.sleep,
		Getenv:      a.getenv,
	}
	return runtime, nil
}

func (a *app) runtime(cmd *cobra.Command) (*runtimeContext, error) {
	paths, cfg, err := a.loadConfig(cmd)
	if err != nil {
		return nil, err
	}
	return a.newRuntime(paths, cfg)
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

// NormalizeError maps domain and HTTP errors to the public CLI exit contract.
func NormalizeError(err error) error {
	if err == nil {
		return nil
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
