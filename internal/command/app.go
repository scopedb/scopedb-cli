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

type credentialFactory func(string, config.Paths) (credential.Store, error)

// Dependencies configures the process boundaries used by the command tree.
type Dependencies struct {
	In              io.Reader
	Out             io.Writer
	ErrOut          io.Writer
	HTTPClient      *http.Client
	CredentialStore credentialFactory
	IsInputTerminal func() bool
	OpenURL         func(string) error
	Now             func() time.Time
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
	openURL           func(string) error
	now               func() time.Time
	getenv            func(string) string
	controlURLFlag    string
	consoleURLFlag    string
	noPromptFlag      bool
}

type runtimeContext struct {
	paths       config.Paths
	config      config.Config
	control     *controlplane.Client
	credentials credential.Store
	auth        *auth.Manager
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
		deps.IsInputTerminal = func() bool {
			file, ok := deps.In.(*os.File)
			if !ok {
				return false
			}
			info, err := file.Stat()
			return err == nil && info.Mode()&os.ModeCharDevice != 0
		}
	}
	if deps.OpenURL == nil {
		deps.OpenURL = openURL
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Getenv == nil {
		deps.Getenv = os.Getenv
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
		openURL:           deps.OpenURL,
		now:               deps.Now,
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
	manager := &auth.Manager{
		ControlURL:  cfg.ControlURL,
		Control:     control,
		Credentials: credentials,
		Now:         a.now,
		Getenv:      a.getenv,
	}
	return &runtimeContext{
		paths:       paths,
		config:      cfg,
		control:     control,
		credentials: credentials,
		auth:        manager,
	}, nil
}

func (a *app) runtime(cmd *cobra.Command) (*runtimeContext, error) {
	paths, cfg, err := a.loadConfig(cmd)
	if err != nil {
		return nil, err
	}
	return a.newRuntime(paths, cfg)
}

func (a *app) promptsDisabled(cmd *cobra.Command) bool {
	if cmd.Root().PersistentFlags().Changed("no-prompt") {
		return a.noPromptFlag
	}
	return a.getenv("SCOPEDB_PROMPT_DISABLED") != ""
}

func (a *app) readLine(ctx context.Context, prompt string) (string, error) {
	if prompt != "" {
		if _, err := fmt.Fprint(a.errOut, prompt); err != nil {
			return "", err
		}
	}
	type input struct {
		val string
		err error
	}
	done := make(chan input, 1)
	go func() {
		val, err := a.input.ReadString('\n')
		done <- input{val, err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-done:
		if result.err != nil && !errors.Is(result.err, io.EOF) {
			return "", result.err
		}
		return strings.TrimSpace(result.val), nil
	}
}

// readVerificationCode hides input on a terminal and still accepts piped stdin.
func (a *app) readVerificationCode(ctx context.Context) (string, error) {
	if !a.isInputTerminal() {
		return a.readLine(ctx, "")
	}
	file, ok := a.in.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return a.readLine(ctx, "Verification code: ")
	}
	restore, err := hideTerminalInput(int(file.Fd()))
	if err != nil {
		return "", fmt.Errorf("hide verification code: %w", err)
	}
	value, readErr := a.readLine(ctx, "Verification code: ")
	restoreErr := restore()
	if _, err := fmt.Fprintln(a.errOut); err != nil {
		return "", err
	}
	if readErr != nil {
		return "", readErr
	}
	if restoreErr != nil {
		return "", fmt.Errorf("restore terminal echo: %w", restoreErr)
	}
	return value, nil
}

func openURL(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("open browser: %w", err)
	}
	return nil
}

// NormalizeError maps domain and HTTP errors to the public CLI exit contract.
func NormalizeError(err error) error {
	if err == nil {
		return nil
	}
	var ready *clierror.Error
	if errors.As(err, &ready) {
		return err
	}
	var interrupted *dataplane.InterruptedError
	if errors.As(err, &interrupted) || errors.Is(err, context.Canceled) {
		return clierror.Wrap(clierror.ExitInterrupted, err.Error(), err)
	}
	var timedOut *dataplane.TimedOutError
	if errors.As(err, &timedOut) {
		hint := "increase --timeout and retry"
		if timedOut.CancelErr != nil {
			hint = "verify the statement's outcome before retrying; it may have completed or still be running"
		}
		return clierror.WithHint(clierror.Wrap(clierror.ExitTemporary, timedOut.Error(), err), hint)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return clierror.WithHint(clierror.Wrap(clierror.ExitTemporary, "operation timed out", err), "increase --timeout and retry")
	}
	if errors.Is(err, auth.ErrNotLoggedIn) {
		return clierror.WithHint(clierror.Wrap(clierror.ExitAuth, "not logged in", err), "run 'scope login'")
	}
	if errors.Is(err, auth.ErrInvalidMachineEnv) {
		return clierror.Wrap(clierror.ExitUsage, err.Error(), err)
	}
	if setupErr := workspaceSetupError(err); setupErr != nil {
		return setupErr
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
			result.Hint = "run 'scope login' or check the active workspace"
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
