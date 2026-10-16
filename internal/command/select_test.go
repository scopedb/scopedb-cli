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
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// rawTerminal stands in for the terminal mode of an interactive session and records the restores,
// so a test can prove every menu path gave the terminal back.
type rawTerminal struct {
	restores int
}

func newMenuApp(input string, raw *rawTerminal, rawError error, inputTerminal bool) (*app, *bytes.Buffer) {
	diagnostics := &bytes.Buffer{}
	instance := newApp(Dependencies{
		In:              strings.NewReader(input),
		Out:             &bytes.Buffer{},
		ErrOut:          diagnostics,
		IsInputTerminal: func() bool { return inputTerminal },
		IsErrorTerminal: func() bool { return true },
		MakeRaw: func() (func(), error) {
			if rawError != nil {
				return nil, rawError
			}
			return func() { raw.restores++ }, nil
		},
	})
	return instance, diagnostics
}

func TestChooseMenuSelectsWithArrowKeys(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  int
	}{
		{"arrow down", "\x1b[B\r", 1},
		{"arrow up wraps to the end", "\x1b[A\r", 2},
		{"j moves down", "j\r", 1},
		{"k wraps to the end", "k\r", 2},
		{"arrow down wraps to the start", "\x1b[B\x1b[B\x1b[B\r", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := &rawTerminal{}
			instance, diagnostics := newMenuApp(tc.input, raw, nil, true)
			choice, err := instance.chooseMenu("How do you want to sign in?", []menuOption{
				{label: "One", note: "recommended"},
				{label: "Two"},
				{label: "Three"},
			})
			require.NoError(t, err)
			require.Equal(t, tc.want, choice)
			require.Equal(t, 1, raw.restores)
			require.Contains(t, diagnostics.String(), "? How do you want to sign in?")
			require.Contains(t, diagnostics.String(), "One (recommended)")
			require.Contains(t, diagnostics.String(), "↑/↓ to navigate · enter to select · q to cancel")
		})
	}
}

func TestChooseMenuSelectsWithADigit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  int
	}{
		{"digit selects", "3\r", 2},
		{"out of range digit is ignored", "9\r", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := &rawTerminal{}
			instance, diagnostics := newMenuApp(tc.input, raw, nil, true)
			choice, err := instance.chooseMenu("Pick", []menuOption{{label: "One"}, {label: "Two"}, {label: "Three"}})
			require.NoError(t, err)
			require.Equal(t, tc.want, choice)
			require.Equal(t, 1, raw.restores)
			require.Contains(t, diagnostics.String(), "✔ "+[]string{"One", "Two", "Three"}[tc.want])
		})
	}
}

func TestChooseMenuRendersTheHighlightInPlace(t *testing.T) {
	raw := &rawTerminal{}
	instance, diagnostics := newMenuApp("j\r", raw, nil, true)
	choice, err := instance.chooseMenu("Pick", []menuOption{{label: "One"}, {label: "Two"}})
	require.NoError(t, err)
	require.Equal(t, 1, choice)
	rendered := diagnostics.String()

	// The first frame draws every line from the question down and returns the cursor to the question.
	require.Contains(t, rendered, "\r\x1b[K? Pick\r\n❯ 1. One\r\n  2. Two\r\n\x1b[K")
	require.Contains(t, rendered, "\x1b[3A")
	// The redraw starts from the question line the previous frame left the cursor on, so it must not
	// move up again; moving up would draw the block above the visible one and leave a duplicate.
	redraw := rendered[strings.Index(rendered, "\x1b[3A")+len("\x1b[3A"):]
	require.True(t, strings.HasPrefix(redraw, "\r\x1b[K? Pick"))
	require.Contains(t, redraw, "? Pick\r\n  1. One\r\n❯ 2. Two\r\n")
	// The selection clears the block from the question line down, then reports the choice.
	require.Contains(t, rendered, "\r\x1b[J✔ Two\r\n")
	require.NotContains(t, rendered, "\x1b[2A")
	require.Equal(t, strings.Count(rendered, "\r\n"), strings.Count(rendered, "\n"))
}

// A lone Escape is one byte with nothing after it. Waiting for a second byte would hang the menu
// until the user pressed another key.
func TestChooseMenuCancelsOnALoneEscape(t *testing.T) {
	reader, writer := io.Pipe()
	raw := &rawTerminal{}
	instance := newApp(Dependencies{
		In:              reader,
		Out:             &bytes.Buffer{},
		ErrOut:          &bytes.Buffer{},
		IsInputTerminal: func() bool { return true },
		IsErrorTerminal: func() bool { return true },
		MakeRaw:         func() (func(), error) { return func() { raw.restores++ }, nil },
	})
	go func() { _, _ = writer.Write([]byte("\x1b")) }()

	done := make(chan error, 1)
	go func() {
		_, err := instance.chooseMenu("Pick", []menuOption{{label: "One"}, {label: "Two"}})
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, errMenuCancelled)
		require.Equal(t, 1, raw.restores)
	case <-time.After(5 * time.Second):
		t.Fatal("the menu waited for a second byte after a lone Escape")
	}
}

func TestChooseMenuAcceptsApplicationCursorKeys(t *testing.T) {
	for input, want := range map[string]int{"\x1bOB\r": 1, "\x1bOA\x1bOB\r": 0, "\x1bOA\r": 1} {
		raw := &rawTerminal{}
		instance, _ := newMenuApp(input, raw, nil, true)
		choice, err := instance.chooseMenu("Pick", []menuOption{{label: "One"}, {label: "Two"}})
		require.NoError(t, err, input)
		require.Equal(t, want, choice, input)
	}
}

func TestChooseMenuCancels(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{"q", "q"},
		{"Ctrl+C", "\x03"},
		{"lone escape", "\x1b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := &rawTerminal{}
			instance, _ := newMenuApp(tc.input, raw, nil, true)
			_, err := instance.chooseMenu("Pick", []menuOption{{label: "One"}, {label: "Two"}})
			require.ErrorIs(t, err, errMenuCancelled)
			require.Equal(t, 1, raw.restores)
		})
	}
}

func TestChooseMenuIgnoresAnUnrecognizedEscapeSequence(t *testing.T) {
	raw := &rawTerminal{}
	instance, _ := newMenuApp("\x1bxq", raw, nil, true)
	_, err := instance.chooseMenu("Pick", []menuOption{{label: "One"}, {label: "Two"}})
	require.ErrorIs(t, err, errMenuCancelled)
	require.Equal(t, 1, raw.restores)
}

func TestChooseMenuRestoresRawModeOnEveryPath(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  int
	}{
		{"selection", "\x1b[B\r", 1},
		{"digit", "2\r", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := &rawTerminal{}
			instance, _ := newMenuApp(tc.input, raw, nil, true)
			choice, err := instance.chooseMenu("Pick", []menuOption{{label: "One"}, {label: "Two"}})
			require.NoError(t, err)
			require.Equal(t, tc.want, choice)
			require.Equal(t, 1, raw.restores)
		})
	}
	raw := &rawTerminal{}
	instance, _ := newMenuApp("q", raw, nil, true)
	_, err := instance.chooseMenu("Pick", []menuOption{{label: "One"}, {label: "Two"}})
	require.ErrorIs(t, err, errMenuCancelled)
	require.Equal(t, 1, raw.restores)
}

func TestChooseMenuRestoresRawModeWhenTheReadFails(t *testing.T) {
	raw := &rawTerminal{}
	instance, _ := newMenuApp("", raw, nil, true)
	instance.input = newFailingReader()
	_, err := instance.chooseMenu("Pick", []menuOption{{label: "One"}})
	require.ErrorContains(t, err, "read failed")
	require.Equal(t, 1, raw.restores)
}

func TestChooseMenuUsesTheNumbersWhenRawModeFails(t *testing.T) {
	raw := &rawTerminal{}
	instance, diagnostics := newMenuApp("2\n", raw, errors.New("not a terminal"), true)
	choice, err := instance.chooseMenu("How do you want to sign in?", []menuOption{
		{label: "Sign in with your browser", note: "recommended"},
		{label: "Sign in with a device code"},
	})
	require.NoError(t, err)
	require.Equal(t, 1, choice)
	require.Zero(t, raw.restores)
	require.Contains(t, diagnostics.String(), "How do you want to sign in?")
	require.Contains(t, diagnostics.String(), "  1. Sign in with your browser (recommended)")
	require.Contains(t, diagnostics.String(), "  2. Sign in with a device code")
	require.Contains(t, diagnostics.String(), "Selection [1-2, q to cancel]: ")
	require.NotContains(t, diagnostics.String(), "✔")
}

func TestChooseMenuNumbersReaskOnInvalidInput(t *testing.T) {
	raw := &rawTerminal{}
	instance, diagnostics := newMenuApp("nope\n9\n1\n", raw, errors.New("not a terminal"), true)
	choice, err := instance.chooseMenu("Pick", []menuOption{{label: "One"}, {label: "Two"}})
	require.NoError(t, err)
	require.Equal(t, 0, choice)
	require.Equal(t, 2, strings.Count(diagnostics.String(), "Enter a number between 1 and 2."))
	require.Equal(t, 3, strings.Count(diagnostics.String(), "Selection [1-2, q to cancel]: "))
}

func TestChooseMenuNumbersCancel(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{"q", "q\n"},
		{"empty line", "\n"},
		{"EOF", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := &rawTerminal{}
			instance, _ := newMenuApp(tc.input, raw, errors.New("not a terminal"), true)
			_, err := instance.chooseMenu("Pick", []menuOption{{label: "One"}})
			require.ErrorIs(t, err, errMenuCancelled)
		})
	}
}

func TestChooseMenuNumbersWhenInputIsNotATerminal(t *testing.T) {
	raw := &rawTerminal{}
	instance, diagnostics := newMenuApp("1\n", raw, nil, false)
	choice, err := instance.chooseMenu("Pick", []menuOption{{label: "One"}, {label: "Two"}})
	require.NoError(t, err)
	require.Equal(t, 0, choice)
	require.Zero(t, raw.restores)
	require.Contains(t, diagnostics.String(), "Selection [1-2, q to cancel]: ")
}

// failingReader returns an error for the first byte, standing in for a terminal that disappeared
// while the menu was open.
type failingReader struct{}

func (r *failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func newFailingReader() *bufio.Reader {
	return bufio.NewReader(&failingReader{})
}
