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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/config"
	"github.com/scopedb/scopedb-cli/internal/controlplane"
	"github.com/scopedb/scopedb-cli/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeControlPlane struct {
	t      *testing.T
	Server *httptest.Server
	URL    string

	AccessToken           string
	RefreshToken          string
	RefreshedAccessToken  string
	RefreshedRefreshToken string
	AuthorizationCode     string
	UserCode              string
	DeviceCode            string
	DeviceOutcomes        []string
	DeviceExpiresIn       int64
	DeviceCompleteURI     *string

	User                controlplane.User
	Workspaces          []controlplane.Workspace
	Details             map[string]controlplane.WorkspaceDetails
	Exchange            controlplane.TokenExchangeResponse
	APIKeys             []controlplane.APIKey
	APIKeyRequests      []controlplane.CreateAPIKeyRequest
	RevokedAPIKeys      []string
	TokenResponseMutate func(*controlplane.TokenSet)

	Issuer         string
	MetadataMutate func(*controlplane.AuthorizationServerMetadata)
	TokenStatus    int
	TokenError     string
	HealthStatus   int
	RevokedStatus  int

	AuthorizationQuery url.Values
	TokenForms         []url.Values
	RevokedTokens      []string
	ExchangeCalls      int
	Refreshes          int
	DevicePolls        int
	mu                 sync.Mutex
}

func newFakeControlPlane(t *testing.T) *fakeControlPlane {
	t.Helper()
	fake := &fakeControlPlane{
		t:                     t,
		AccessToken:           "oat_access",
		RefreshToken:          "ort_refresh",
		RefreshedAccessToken:  "oat_access",
		RefreshedRefreshToken: "ort_refresh",
		AuthorizationCode:     "code-1",
		UserCode:              "BCDF-GHJK-LMNP",
		DeviceCode:            "device-1",
		User:                  controlplane.User{ID: "user-1", Email: "dev@example.com", Status: "active"},
		Details:               map[string]controlplane.WorkspaceDetails{},
	}
	fake.Server = httptest.NewServer(http.HandlerFunc(fake.serve))
	fake.URL = fake.Server.URL
	fake.Issuer = fake.Server.URL
	t.Cleanup(fake.Server.Close)
	return fake
}

func (f *fakeControlPlane) metadata() controlplane.AuthorizationServerMetadata {
	metadata := controlplane.AuthorizationServerMetadata{
		Issuer:                                     f.Issuer,
		AuthorizationEndpoint:                      f.URL + "/oauth/authorize",
		DeviceAuthorizationEndpoint:                f.URL + "/oauth/device/authorization",
		TokenEndpoint:                              f.URL + "/oauth/token",
		RevocationEndpoint:                         f.URL + "/oauth/revoke",
		ResponseTypesSupported:                     []string{"code"},
		GrantTypesSupported:                        []string{"authorization_code", controlplane.GrantTypeDeviceCode, "refresh_token"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		TokenEndpointAuthMethodsSupported:          []string{"none"},
		RevocationEndpointAuthMethodsSupported:     []string{"none"},
		ScopesSupported:                            []string{"platform"},
		AuthorizationResponseIssParameterSupported: true,
	}
	if f.MetadataMutate != nil {
		f.MetadataMutate(&metadata)
	}
	return metadata
}

func (f *fakeControlPlane) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/.well-known/oauth-authorization-server":
		f.writeJSON(w, http.StatusOK, f.metadata())
	case r.URL.Path == "/oauth/token":
		f.serveToken(w, r)
	case r.URL.Path == "/oauth/revoke":
		assert.NoError(f.t, r.ParseForm())
		f.mu.Lock()
		f.RevokedTokens = append(f.RevokedTokens, r.PostForm.Get("token"))
		f.mu.Unlock()
		status := f.RevokedStatus
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
	case r.URL.Path == "/oauth/device/authorization":
		expiresIn := f.DeviceExpiresIn
		if expiresIn <= 0 {
			expiresIn = 600
		}
		if f.DeviceCode == "" {
			f.DeviceCode = "device-1"
		}
		complete := "https://console.example.com/oauth/device#user_code=" + f.UserCode
		if f.DeviceCompleteURI != nil {
			complete = *f.DeviceCompleteURI
		}
		f.writeJSON(w, http.StatusOK, map[string]any{
			"device_code":               f.DeviceCode,
			"user_code":                 f.UserCode,
			"verification_uri":          "https://console.example.com/oauth/device",
			"verification_uri_complete": complete,
			"expires_in":                expiresIn,
			"interval":                  0,
		})
	case r.URL.Path == "/api/user":
		f.writeJSON(w, http.StatusOK, f.User)
	case r.URL.Path == "/api/workspaces" && r.Method == http.MethodGet:
		f.writeJSON(w, http.StatusOK, controlplane.WorkspacesResponse{Workspaces: f.workspaces()})
	case r.URL.Path == "/healthz":
		status := f.HealthStatus
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
	case strings.HasPrefix(r.URL.Path, "/api/workspaces/"):
		f.serveWorkspace(w, r)
	default:
		f.t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func (f *fakeControlPlane) serveWorkspace(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/workspaces/")
	if strings.HasSuffix(path, "/token-exchange") {
		f.mu.Lock()
		f.ExchangeCalls++
		f.mu.Unlock()
		f.writeJSON(w, http.StatusOK, f.Exchange)
		return
	}
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 2 && parts[1] == "api-keys" {
		f.serveAPIKeys(w, r)
		return
	}
	if len(parts) == 2 && strings.HasPrefix(parts[1], "api-keys/") {
		f.mu.Lock()
		f.RevokedAPIKeys = append(f.RevokedAPIKeys, strings.TrimPrefix(parts[1], "api-keys/"))
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	details, ok := f.Details[path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	f.writeJSON(w, http.StatusOK, details)
}

func (f *fakeControlPlane) serveAPIKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys := make([]controlplane.APIKey, len(f.APIKeys))
		copy(keys, f.APIKeys)
		f.writeJSON(w, http.StatusOK, keys)
	case http.MethodPost:
		var request controlplane.CreateAPIKeyRequest
		assert.NoError(f.t, json.NewDecoder(r.Body).Decode(&request))
		f.mu.Lock()
		f.APIKeyRequests = append(f.APIKeyRequests, request)
		f.mu.Unlock()
		f.writeJSON(w, http.StatusCreated, controlplane.APIKey{
			ID: "key-new", Name: request.Name, Tags: request.Tags, Status: "active",
			CreatedAt: time.Now().UTC(), ExpiresAt: request.ExpiresAt, Key: "secret-key",
		})
	default:
		f.t.Errorf("unexpected API key method: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func (f *fakeControlPlane) serveToken(w http.ResponseWriter, r *http.Request) {
	assert.NoError(f.t, r.ParseForm())
	form := url.Values{}
	for key, values := range r.PostForm {
		form[key] = values
	}
	f.mu.Lock()
	f.TokenForms = append(f.TokenForms, form)
	if form.Get("grant_type") == "refresh_token" {
		f.Refreshes++
	}
	f.mu.Unlock()

	if f.TokenStatus != 0 {
		code := f.TokenError
		if code == "" {
			code = "server_error"
		}
		f.writeJSON(w, f.TokenStatus, map[string]string{"error": code, "error_description": code})
		return
	}
	switch form.Get("grant_type") {
	case "authorization_code":
		challenge := f.AuthorizationQuery.Get("code_challenge")
		if challenge == "" || challenge != challengeFor(form.Get("code_verifier")) {
			f.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "the code_verifier does not match"})
			return
		}
		if form.Get("code") != f.AuthorizationCode {
			f.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "the code is unknown"})
			return
		}
		f.writeJSON(w, http.StatusOK, f.tokenSet(f.AccessToken, f.RefreshToken))
	case "refresh_token":
		if form.Get("refresh_token") != f.RefreshToken {
			f.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "the refresh token is unknown"})
			return
		}
		f.writeJSON(w, http.StatusOK, f.tokenSet(f.RefreshedAccessToken, f.RefreshedRefreshToken))
	case controlplane.GrantTypeDeviceCode:
		f.mu.Lock()
		index := f.DevicePolls
		f.DevicePolls++
		f.mu.Unlock()
		outcome := ""
		if index < len(f.DeviceOutcomes) {
			outcome = f.DeviceOutcomes[index]
		}
		if outcome != "" {
			f.writeJSON(w, http.StatusBadRequest, map[string]string{"error": outcome, "error_description": outcome})
			return
		}
		f.writeJSON(w, http.StatusOK, f.tokenSet(f.AccessToken, f.RefreshToken))
	default:
		f.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (f *fakeControlPlane) tokenSet(access, refresh string) controlplane.TokenSet {
	set := controlplane.TokenSet{
		AccessToken:           access,
		TokenType:             "Bearer",
		ExpiresIn:             3600,
		RefreshToken:          refresh,
		RefreshTokenExpiresIn: 1209600,
		Scope:                 controlplane.ScopePlatform,
	}
	if f.TokenResponseMutate != nil {
		f.TokenResponseMutate(&set)
	}
	return set
}

func (f *fakeControlPlane) workspaces() []controlplane.Workspace {
	if f.Workspaces == nil {
		return []controlplane.Workspace{}
	}
	return f.Workspaces
}

func (f *fakeControlPlane) writeJSON(w http.ResponseWriter, status int, body any) {
	w.WriteHeader(status)
	assert.NoError(f.t, json.NewEncoder(w).Encode(body))
}

func (f *fakeControlPlane) authorizationURL(t *testing.T) func(string) error {
	t.Helper()
	return func(target string) error {
		parsed, err := url.Parse(target)
		require.NoError(t, err)
		f.AuthorizationQuery = parsed.Query()
		callback, err := url.Parse(parsed.Query().Get("redirect_uri"))
		require.NoError(t, err)
		query := callback.Query()
		query.Set("code", f.AuthorizationCode)
		query.Set("state", parsed.Query().Get("state"))
		query.Set("iss", f.Issuer)
		callback.RawQuery = query.Encode()
		response, err := http.Get(callback.String())
		if err != nil {
			return err
		}
		return response.Body.Close()
	}
}

func workspaceFixture(id, name string) controlplane.Workspace {
	return controlplane.Workspace{
		ID:                 id,
		DisplayName:        &name,
		Provider:           "aws",
		Region:             "us-east-1",
		ProvisioningStatus: "ready",
	}
}

func scheduledForDeletionFixture(id, name string) controlplane.Workspace {
	workspace := workspaceFixture(id, name)
	deadline := time.Now().Add(time.Hour)
	workspace.ScheduledForDeletionAt = &deadline
	return workspace
}

func profileKeyFor(controlURL string) string {
	digest := sha256.Sum256([]byte(controlURL))
	return hex.EncodeToString(digest[:])
}

func challengeFor(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func setupCLITest(t *testing.T) (*fakeControlPlane, *credential.PlaintextStore) {
	t.Helper()
	fake := newFakeControlPlane(t)
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	t.Setenv("SCOPEDB_CONTROL_URL", fake.URL)
	t.Setenv("SCOPEDB_CONSOLE_URL", "")
	t.Setenv("SCOPEDB_CREDENTIAL_STORE", "plaintext")
	paths, err := config.ResolvePaths()
	require.NoError(t, err)
	return fake, credential.NewPlaintextStore(paths.CredentialsFile)
}

func saveStoredLogin(t *testing.T, store *credential.PlaintextStore, controlURL, workspaceID string) credential.State {
	t.Helper()
	return saveLogin(t, store, controlURL, workspaceID, time.Now().Add(time.Hour), time.Now().Add(24*time.Hour))
}

func saveExpiredLogin(t *testing.T, store *credential.PlaintextStore, controlURL, workspaceID string) credential.State {
	t.Helper()
	return saveLogin(t, store, controlURL, workspaceID, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
}

func saveLogin(t *testing.T, store *credential.PlaintextStore, controlURL, workspaceID string, accessExpiresAt, refreshExpiresAt time.Time) credential.State {
	t.Helper()
	state := credential.State{
		AccessToken:           "oat_access",
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshToken:          "ort_refresh",
		RefreshTokenExpiresAt: refreshExpiresAt,
		WorkspaceID:           workspaceID,
	}
	require.NoError(t, store.Save(controlURL, state))
	return state
}

func runFakeCommand(t *testing.T, fake *fakeControlPlane, args ...string) (string, string, error) {
	t.Helper()
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In:      strings.NewReader(""),
		Out:     &out,
		ErrOut:  &diagnostics,
		Getenv:  func(string) string { return "" },
		Sleep:   func(time.Duration) {},
		OpenURL: fake.authorizationURL(t),
	})
	root.SetArgs(append([]string{"--control-url", fake.URL}, args...))
	err := root.ExecuteContext(t.Context())
	for _, secret := range []string{"oat_access", "ort_refresh", "code-1", "device-1", "oat_rotated", "ort_rotated", "private-access-secret", "private-refresh-secret", "legacy-secret"} {
		require.NotContains(t, out.String()+diagnostics.String(), secret)
	}
	return out.String(), diagnostics.String(), err
}

func runCommand(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In:     strings.NewReader(""),
		Out:    &out,
		ErrOut: &diagnostics,
		Getenv: func(string) string { return "" },
		Sleep:  func(time.Duration) {},
	})
	root.SetArgs(args)
	err := root.ExecuteContext(t.Context())
	for _, secret := range []string{"oat_access", "ort_refresh", "code-1", "device-1", "oat_rotated", "ort_rotated"} {
		require.NotContains(t, out.String()+diagnostics.String(), secret)
	}
	return out.String(), diagnostics.String(), err
}

type loginScenario struct {
	input           string
	inputTerminal   bool
	errorTerminal   bool
	getenv          func(string) string
	credentialStore func(string, config.Paths) (credential.Store, error)
	openURL         func(string) error
	args            []string
}

func runLoginScenario(t *testing.T, fake *fakeControlPlane, scenario loginScenario) (string, string, error) {
	t.Helper()
	getenv := scenario.getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	openURL := scenario.openURL
	if openURL == nil {
		openURL = fake.authorizationURL(t)
	}
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In:              strings.NewReader(scenario.input),
		Out:             &out,
		ErrOut:          &diagnostics,
		Getenv:          getenv,
		Sleep:           func(time.Duration) {},
		OpenURL:         openURL,
		CredentialStore: scenario.credentialStore,
		IsInputTerminal: func() bool { return scenario.inputTerminal },
		IsErrorTerminal: func() bool { return scenario.errorTerminal },
	})
	args := scenario.args
	if len(args) == 0 || args[0] != "auth" {
		args = append([]string{"auth", "login", "--insecure-storage"}, args...)
	}
	root.SetArgs(append([]string{"--control-url", fake.URL}, args...))
	err := root.ExecuteContext(t.Context())
	for _, secret := range []string{"oat_access", "ort_refresh", "code-1", "device-1", "oat_rotated", "ort_rotated", "private-access-secret", "private-refresh-secret", "legacy-secret"} {
		require.NotContains(t, out.String()+diagnostics.String(), secret)
	}
	return out.String(), diagnostics.String(), err
}

func runInteractiveCommand(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In:              strings.NewReader("\r"),
		Out:             &out,
		ErrOut:          &diagnostics,
		Getenv:          func(string) string { return "" },
		Sleep:           func(time.Duration) {},
		IsInputTerminal: func() bool { return true },
		IsErrorTerminal: func() bool { return true },
	})
	root.SetArgs(args)
	err := root.ExecuteContext(t.Context())
	return out.String(), diagnostics.String(), err
}

func runDeviceLogin(t *testing.T, fake *fakeControlPlane, flags ...string) (string, string, error) {
	t.Helper()
	args := append([]string{"auth", "login", "--insecure-storage", "--use-device-code", "--no-browser"}, flags...)
	return runLoginScenario(t, fake, loginScenario{
		inputTerminal: true,
		errorTerminal: true,
		args:          args,
	})
}

func runInteractiveLogin(t *testing.T, fake *fakeControlPlane, input string, flags ...string) (string, string, error) {
	t.Helper()
	args := append([]string{"auth", "login", "--insecure-storage"}, flags...)
	return runLoginScenario(t, fake, loginScenario{
		input:         input,
		inputTerminal: true,
		errorTerminal: true,
		args:          args,
	})
}
