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

//go:build darwin || linux

package command

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func installBrowserLauncher(t *testing.T, script string) {
	t.Helper()
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	directory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(directory, name), []byte("#!/bin/sh\n"+script), 0o700))
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DISPLAY", ":0")
}

func TestLoginContinuesWhenBrowserLauncherExitsUnsuccessfully(t *testing.T) {
	fake, store := setupCLITest(t)
	installBrowserLauncher(t, "exit 17\n")
	var out, diagnostics bytes.Buffer
	root := NewRoot(Dependencies{
		In:     strings.NewReader(""),
		Out:    &out,
		ErrOut: &diagnostics,
		OpenURL: func(target string) error {
			err := openURL(target, os.Getenv)
			require.ErrorContains(t, err, "open browser: exit status 17")
			require.Contains(t, diagnostics.String(), target)
			// The user opens the printed URL manually after the launcher fails.
			require.NoError(t, fake.authorizationURL(t)(target))
			return err
		},
		Sleep: func(time.Duration) {},
	})
	root.SetArgs([]string{"auth", "login"})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	require.NoError(t, root.ExecuteContext(ctx))
	require.Contains(t, diagnostics.String(), "scope auth login --use-device-code")
	require.Contains(t, out.String(), "Logged in as dev@example.com.")
	require.Len(t, fake.TokenForms, 1)
	require.Equal(t, "authorization_code", fake.TokenForms[0].Get("grant_type"))
	require.Zero(t, fake.DevicePolls)
	state, err := store.Load(fake.URL)
	require.NoError(t, err)
	require.Equal(t, fake.RefreshToken, state.RefreshToken)
}

func TestConsoleReportsBrowserLauncherFailure(t *testing.T) {
	setupCLITest(t)
	installBrowserLauncher(t, "exit 17\n")
	var out bytes.Buffer
	root := NewRoot(Dependencies{Out: &out})
	root.SetArgs([]string{"console", "--open", "--format", "json"})
	err := root.ExecuteContext(t.Context())
	require.ErrorContains(t, err, "open browser: exit status 17")
	require.Empty(t, out.String())
}

func TestOpenURLDoesNotWaitForTheBrowserToClose(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "release")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	release, err := os.OpenFile(fifo, os.O_RDWR, 0o600)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = release.WriteString("done\n")
		_ = release.Close()
	})
	t.Setenv("SCOPEDB_TEST_BROWSER_RELEASE", fifo)
	installBrowserLauncher(t, "read -r release < \"$SCOPEDB_TEST_BROWSER_RELEASE\"\n")
	opened := make(chan error, 1)
	go func() { opened <- openURL("https://console.example.com", os.Getenv) }()

	select {
	case err := <-opened:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("opening the URL waited for the browser to close")
	}
}
