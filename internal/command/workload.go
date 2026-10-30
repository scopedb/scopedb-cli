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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/scopedb/scopedb-cli/internal/auth"
	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/scopedb/scopedb-cli/internal/output"
	"github.com/spf13/cobra"
)

const (
	envOIDCTokenFile    = "SCOPEDB_OIDC_TOKEN_FILE"
	envOIDCToken        = "SCOPEDB_OIDC_TOKEN"
	githubRequestURLEnv = "ACTIONS_ID_TOKEN_REQUEST_URL"
	githubRequestToken  = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"

	// maxOIDCTokenSize matches the control plane's bearer token bound.
	maxOIDCTokenSize = 16 << 10
	// maxOIDCResponseSize bounds the provider's token response document.
	maxOIDCResponseSize = 64 << 10

	// The exchange retries only when the server directs it to, and the job's
	// OIDC token is short-lived, so attempts and the wait between them stay small.
	workloadExchangeAttempts = 3
	workloadExchangeMaxWait  = 30 * time.Second
)

// workloadLogin performs the non-interactive CI login: it resolves the job's
// OIDC token, exchanges it at the control plane for a workspace-bound
// data-plane credential, and stores the result as a workload login.
func (a *app) workloadLogin(cmd *cobra.Command, runtime *runtimeContext, workspaceID, format string) error {
	token, err := a.resolveOIDCToken(cmd.Context(), runtime.config.ControlURL)
	if err != nil {
		return err
	}
	exchange, err := a.exchangeWorkloadIdentity(cmd.Context(), runtime, workspaceID, token)
	if err != nil {
		var controlErr *controlplane.Error
		if errors.As(err, &controlErr) && controlErr.Status == http.StatusNotFound {
			return clierror.WithHint(
				clierror.New(clierror.ExitUsage, "this ScopeDB deployment does not support workload identity yet"),
				"upgrade the platform",
			)
		}
		if errors.As(err, &controlErr) && controlErr.Status == http.StatusUnauthorized {
			result := clierror.Wrap(clierror.ExitAuth, controlErr.Error(), err)
			result.RequestID = controlErr.RequestID
			result.Hint = "check that the CI OIDC token audience is the control plane origin and its subject exactly matches an enabled workload identity policy in this workspace"
			return result
		}
		return err
	}
	if !strings.EqualFold(exchange.TokenType, "Bearer") || exchange.AccessToken == "" || exchange.Endpoint == "" || exchange.ExpiresAt.IsZero() {
		return errors.New("the workload identity exchange returned an invalid credential")
	}
	bound := exchange.WorkspaceID
	if bound == "" {
		bound = workspaceID
	}
	state := credential.State{
		Kind:            credential.KindWorkload,
		WorkspaceID:     bound,
		Endpoint:        exchange.Endpoint,
		APIKey:          exchange.AccessToken,
		APIKeyExpiresAt: exchange.ExpiresAt.UTC(),
		Workload: &credential.WorkloadIdentity{
			PolicyID: exchange.Identity.PolicyID,
			Name:     exchange.Identity.Name,
			Provider: exchange.Identity.Provider,
			Subject:  exchange.Identity.Subject,
		},
	}
	if err := runtime.persistWorkloadLogin(cmd.Context(), state); err != nil {
		return err
	}

	result := workloadLoginResult{
		LoginKind:   credential.KindWorkload,
		WorkspaceID: bound,
		Endpoint:    exchange.Endpoint,
		ExpiresAt:   state.APIKeyExpiresAt.Format(time.RFC3339),
		Identity:    exchange.Identity,
	}
	if format == structuredFormatJSON {
		return writeJSON(a.out, result)
	}
	name := exchange.Identity.Name
	if name == "" {
		name = "unnamed"
	}
	if _, err := fmt.Fprintf(a.out, "Logged in as workload identity %s (%s).\n", name, exchange.Identity.Subject); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.out, "Using workspace %s; the credential expires at %s.\n", bound, state.APIKeyExpiresAt.Format(time.RFC3339))
	return err
}

// exchangeWorkloadIdentity calls the control plane exchange, retrying only when the
// server directs a retry with a retryable error carrying Retry-After (an unavailable
// provider or an address rate limit). The same OIDC token is reused across attempts;
// a credential-limit 429 carries no Retry-After and is never retried.
func (a *app) exchangeWorkloadIdentity(ctx context.Context, runtime *runtimeContext, workspaceID, token string) (controlplane.WorkloadIdentityExchangeResponse, error) {
	var exchange controlplane.WorkloadIdentityExchangeResponse
	for attempt := 1; ; attempt++ {
		var err error
		exchange, err = runtime.control.ExchangeWorkloadIdentity(ctx, workspaceID, token)
		var controlErr *controlplane.Error
		if !errors.As(err, &controlErr) || !controlErr.Retryable || controlErr.RetryAfter <= 0 ||
			attempt >= workloadExchangeAttempts {
			return exchange, err
		}
		wait := min(controlErr.RetryAfter, workloadExchangeMaxWait)
		if _, err := fmt.Fprintf(a.errOut, "workload identity exchange temporarily unavailable; retrying in %s (attempt %d of %d)\n",
			wait.Round(time.Second), attempt+1, workloadExchangeAttempts); err != nil {
			return exchange, err
		}
		if err := a.waitForExchangeRetry(ctx, wait); err != nil {
			return exchange, err
		}
	}
}

// waitForExchangeRetry pauses for the server-directed delay while still aborting
// promptly on cancellation; the sleep seam itself cannot be interrupted.
func (a *app) waitForExchangeRetry(ctx context.Context, wait time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		a.sleep(wait)
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type workloadLoginResult struct {
	LoginKind   string                               `json:"login_kind"`
	WorkspaceID string                               `json:"workspace_id"`
	Endpoint    string                               `json:"endpoint"`
	ExpiresAt   string                               `json:"expires_at"`
	Identity    controlplane.WorkloadIdentitySummary `json:"identity"`
}

// persistWorkloadLogin stores the credential, then the configuration, rolling
// the credential back when the configuration write fails so a CI job does not
// leave a credential behind in a directory it cannot use.
func (r *runtimeContext) persistWorkloadLogin(ctx context.Context, state credential.State) error {
	previous, found, writtenKey, saveErr := r.auth.SaveWorkloadLogin(ctx, state)
	if saveErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(saveErr, context.Canceled) || errors.Is(saveErr, context.DeadlineExceeded) {
			return saveErr
		}
		if errors.Is(saveErr, auth.ErrAlreadyLoggedIn) {
			return clierror.WithHint(clierror.New(clierror.ExitAuth, "an interactive login is already stored"), "run 'scope auth logout' first")
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
		rollbackErr := r.auth.RestoreLogin(ctx, previous, found, writtenKey)
		if rollbackErr != nil {
			result.Message += " and previous credentials could not be restored"
			result.Err = errors.Join(result.Err, rollbackErr)
			result.Hint = "check config and credential store access before retrying"
		}
		return result
	}
}

// resolveOIDCToken finds the CI job's identity token. The token is a short-lived
// assertion presented once to the exchange; it is never written to the
// credential store and never printed.
func (a *app) resolveOIDCToken(ctx context.Context, controlURL string) (string, error) {
	if path := strings.TrimSpace(a.getenv(envOIDCTokenFile)); path != "" {
		return readOIDCTokenFile(path)
	}
	if value := a.getenv(envOIDCToken); strings.TrimSpace(value) != "" {
		return checkOIDCToken(value)
	}
	if a.getenv(githubRequestURLEnv) != "" && a.getenv(githubRequestToken) != "" {
		audience, err := controlOrigin(controlURL)
		if err != nil {
			return "", err
		}
		return a.githubOIDCToken(ctx, a.getenv(githubRequestURLEnv), a.getenv(githubRequestToken), audience)
	}
	return "", clierror.WithHint(
		clierror.New(clierror.ExitUsage, "no CI identity token is available for this job"),
		fmt.Sprintf("set %s or %s to the OIDC token issued for this job; on GitHub Actions, grant the job id-token: write permission", envOIDCTokenFile, envOIDCToken),
	)
}

// controlOrigin is the OIDC audience the exchange verifies: the configured
// control-plane origin without a path, query, or fragment.
func controlOrigin(controlURL string) (string, error) {
	parsed, err := url.Parse(controlURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid control URL %q", controlURL)
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func readOIDCTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", envOIDCTokenFile, err)
	}
	if len(data) > maxOIDCTokenSize {
		return "", fmt.Errorf("%s exceeds the %d KiB token limit", envOIDCTokenFile, maxOIDCTokenSize>>10)
	}
	return checkOIDCToken(string(data))
}

func checkOIDCToken(raw string) (string, error) {
	token := strings.TrimSpace(raw)
	if token == "" {
		return "", errors.New("the CI identity token is empty")
	}
	if len(token) > maxOIDCTokenSize {
		return "", fmt.Errorf("the CI identity token exceeds the %d KiB limit", maxOIDCTokenSize>>10)
	}
	return token, nil
}

// githubOIDCToken asks GitHub Actions for an OIDC token scoped to the
// control-plane audience, using the job's injected request URL and token.
func (a *app) githubOIDCToken(ctx context.Context, requestURL, requestToken, audience string) (string, error) {
	endpoint, err := url.Parse(requestURL)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return "", errors.New("the GitHub Actions OIDC request URL is invalid")
	}
	if endpoint.User != nil {
		return "", errors.New("the GitHub Actions OIDC request URL must not contain user information")
	}
	query := endpoint.Query()
	query.Set("audience", audience)
	endpoint.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", fmt.Errorf("create GitHub Actions OIDC request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+requestToken)
	httpClient := a.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("cannot reach the GitHub Actions OIDC endpoint: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(response.Body, maxOIDCResponseSize+1))
	if err != nil {
		return "", fmt.Errorf("read the GitHub Actions OIDC response: %w", err)
	}
	if int64(len(data)) > maxOIDCResponseSize {
		return "", errors.New("the GitHub Actions OIDC response is too large")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("the GitHub Actions OIDC endpoint returned %s", response.Status)
	}
	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", fmt.Errorf("the GitHub Actions OIDC response is invalid: %w", err)
	}
	token, err := checkOIDCToken(payload.Value)
	if err != nil {
		return "", fmt.Errorf("the GitHub Actions OIDC response carries no usable token: %w", err)
	}
	return token, nil
}

// workloadStatusView reports a CI workload login without contacting the control
// plane: the credential is workspace-bound and carries no account.
func (a *app) renderWorkloadStatus(out io.Writer, format string, runtime *runtimeContext, state credential.State) error {
	view := statusView{
		ControlURL:       runtime.config.ControlURL,
		LoginKind:        credential.KindWorkload,
		CredentialSource: state.Source,
		WorkspaceID:      state.WorkspaceID,
		Endpoint:         state.Endpoint,
	}
	if state.Workload != nil {
		view.WorkloadPolicy = state.Workload.Name
		view.WorkloadProvider = state.Workload.Provider
		view.WorkloadSubject = state.Workload.Subject
	}
	if state.Source == credential.SourcePlaintext {
		view.CredentialFile = runtime.paths.CredentialsFile
	}
	if !state.APIKeyExpiresAt.IsZero() {
		view.CredentialExpiresAt = state.APIKeyExpiresAt.UTC().Format(time.RFC3339)
		if !state.APIKeyExpiresAt.After(a.now().UTC()) {
			if _, err := fmt.Fprintln(a.errOut, "The workload credential has expired; run 'scope auth login --workload-identity' to log in again."); err != nil {
				return err
			}
		}
	}
	if format == structuredFormatJSON {
		return writeJSON(out, view)
	}
	t := output.NewTable("FIELD", "VALUE")
	t.AppendRow(table.Row{"Credential source", view.CredentialSource})
	if view.CredentialFile != "" {
		t.AppendRow(table.Row{"Credential file", view.CredentialFile})
	}
	t.AppendRows([]table.Row{
		{"Login kind", view.LoginKind},
		{"Workload policy", emptyDash(view.WorkloadPolicy)},
		{"Provider", emptyDash(view.WorkloadProvider)},
		{"Subject", emptyDash(view.WorkloadSubject)},
		{"Workspace ID", emptyDash(view.WorkspaceID)},
		{"Endpoint", emptyDash(view.Endpoint)},
		{"Credential expires", emptyDash(view.CredentialExpiresAt)},
		{"Control URL", emptyDash(view.ControlURL)},
	})
	return output.WriteTable(out, t)
}
