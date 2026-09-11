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
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/stretchr/testify/require"
)

func TestReadLineReturnsTrimmedValue(t *testing.T) {
	var prompt strings.Builder
	a := newApp(Dependencies{
		In:     strings.NewReader("  user@example.com  \n"),
		Out:    io.Discard,
		ErrOut: &prompt,
	})

	value, err := a.readLine(context.Background(), "Email: ")

	require.NoError(t, err)
	require.Equal(t, "user@example.com", value)
	require.Equal(t, "Email: ", prompt.String())
}

func TestLoginStopsWhenContextIsCanceledAtPrompt(t *testing.T) {
	t.Setenv("SCOPEDB_CONFIG_DIR", t.TempDir())
	reader, writer := io.Pipe()
	t.Cleanup(func() {
		_ = writer.Close()
		_ = reader.Close()
	})
	prompt := newPromptSignal()
	root := NewRoot(Dependencies{
		In:              reader,
		Out:             io.Discard,
		ErrOut:          prompt,
		IsInputTerminal: func() bool { return true },
	})
	root.SetArgs([]string{"login"})
	ctx, cancel := context.WithCancel(context.Background())
	commandErr := make(chan error, 1)
	go func() {
		commandErr <- root.ExecuteContext(ctx)
	}()

	<-prompt.written
	cancel()

	select {
	case err := <-commandErr:
		require.Equal(t, clierror.ExitInterrupted, clierror.ExitCode(err))
	case <-time.After(10 * time.Second):
		t.Fatal("login kept waiting for input after the context was canceled")
	}
}

type promptSignal struct {
	once    sync.Once
	written chan struct{}
}

func newPromptSignal() *promptSignal {
	return &promptSignal{written: make(chan struct{})}
}

func (s *promptSignal) Write(p []byte) (int, error) {
	s.once.Do(func() { close(s.written) })
	return len(p), nil
}
