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
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var (
	errMenuCancelled   = errors.New("menu cancelled")
	errMenuInterrupted = errors.New("menu interrupted")
)

type menuOption struct {
	label string
	note  string
}

const (
	// The cursor glyph needs a UTF-8 terminal, which the arrow-key menu already requires.
	menuCursor = "❯ "
	menuIndent = "  "

	// cursorUp moves the cursor to the start of the line n rows above, for an in-place redraw.
	cursorUp = "\x1b[%dA"
	// clearLine clears from the cursor to the end of the line.
	clearLine = "\r\x1b[K"
	// clearBlock clears from the cursor to the end of the screen, removing the menu and its hint.
	clearBlock = "\r\x1b[J"
	// rawNewline ends a line while the terminal is in raw mode, where the driver no longer turns a
	// line feed into carriage return plus line feed.
	rawNewline = "\r\n"
)

func menuHint(quit string) string {
	return "↑/↓ to navigate · enter to select · q to " + quit
}

func (a *app) chooseMenu(question string, options []menuOption) (int, error) {
	return a.chooseMenuWith(question, options, "cancel")
}

func (a *app) chooseMenuWith(question string, options []menuOption, quit string) (int, error) {
	if len(options) == 0 {
		return 0, errors.New("menu needs at least one option")
	}
	if a.isInputTerminal != nil && a.isInputTerminal() {
		restore, err := a.makeRaw()
		if err == nil {
			return a.chooseMenuRaw(question, options, restore, quit)
		}
	}
	return a.chooseMenuNumbered(question, options, quit)
}

func (a *app) chooseMenuRaw(question string, options []menuOption, restore func(), quit string) (int, error) {
	selected := 0
	defer restore()
	hint := menuHint(quit)

	if err := a.renderMenuFrame(question, options, selected, hint); err != nil {
		return 0, err
	}
	for {
		key, err := a.readMenuKey()
		if err != nil {
			_ = a.eraseMenu()
			return 0, err
		}
		switch key {
		case "up":
			selected = (selected - 1 + len(options)) % len(options)
		case "down":
			selected = (selected + 1) % len(options)
		case "enter":
			if err := a.eraseMenu(); err != nil {
				return 0, err
			}
			if _, err := fmt.Fprintf(a.errOut, "✔ %s%s", options[selected].label, rawNewline); err != nil {
				return 0, err
			}
			return selected, nil
		case "cancel":
			if err := a.eraseMenu(); err != nil {
				return 0, err
			}
			return 0, errMenuCancelled
		default:
			if digit, ok := menuDigit(key); ok && digit < len(options) {
				selected = digit
			}
		}
		if err := a.renderMenuFrame(question, options, selected, hint); err != nil {
			return 0, err
		}
	}
}

func (a *app) readMenuKey() (string, error) {
	key, err := a.input.ReadByte()
	if err != nil {
		return "", err
	}
	switch key {
	case '\r', '\n':
		return "enter", nil
	case 0x03:
		return "", errMenuInterrupted
	case 'q':
		return "cancel", nil
	case '\x1b':
		// A lone Escape arrives as one byte and nothing follows it, so an empty buffer means cancel
		// instead of a read that waits for a key the user never pressed. A key sequence arrives in
		// one write and stays buffered, so the arrow keys are still recognized.
		if a.input.Buffered() == 0 {
			return "cancel", nil
		}
		next, err := a.input.ReadByte()
		if err != nil {
			return "cancel", nil
		}
		switch next {
		case '[':
			return a.readCSIKey()
		case 'O': // application cursor keys mode, a three-byte sequence
			final, err := a.input.ReadByte()
			if err != nil {
				return "", nil
			}
			return arrowKey(final), nil
		}
		return "", nil
	case 'k':
		return "up", nil
	case 'j':
		return "down", nil
	default:
		return string(key), nil
	}
}

// renderMenuFrame draws the question and options, and leaves the cursor on the question line with the
// trailing cursorUp. Every frame starts from that same position, so a redraw replaces the block
// instead of drawing a second one above it.
// readCSIKey consumes a full control sequence, including parameters and intermediates, so a suffix
// such as ";5A" cannot become a digit hotkey on the next read.
func (a *app) readCSIKey() (string, error) {
	for {
		value, err := a.input.ReadByte()
		if err != nil {
			return "", err
		}
		if value >= 0x40 && value <= 0x7e {
			return arrowKey(value), nil
		}
	}
}

func arrowKey(value byte) string {
	switch value {
	case 'A':
		return "up"
	case 'B':
		return "down"
	default:
		return ""
	}
}

func (a *app) renderMenuFrame(question string, options []menuOption, selected int, hint string) error {
	var frame strings.Builder
	frame.WriteString(clearLine)
	frame.WriteString("? ")
	frame.WriteString(question)
	frame.WriteString(rawNewline)
	for index, option := range options {
		if index == selected {
			frame.WriteString(menuCursor)
		} else {
			frame.WriteString(menuIndent)
		}
		fmt.Fprintf(&frame, "%d. %s", index+1, option.label)
		if option.note != "" {
			fmt.Fprintf(&frame, " (%s)", option.note)
		}
		frame.WriteString(rawNewline)
	}
	frame.WriteString("\x1b[K")
	frame.WriteString(hint)
	fmt.Fprintf(&frame, cursorUp, len(options)+1)
	_, err := io.WriteString(a.errOut, frame.String())
	return err
}

func (a *app) eraseMenu() error {
	_, err := io.WriteString(a.errOut, clearBlock)
	return err
}

func (a *app) chooseMenuNumbered(question string, options []menuOption, quit string) (int, error) {
	var prompt strings.Builder
	prompt.WriteString(question)
	prompt.WriteString("\n")
	for index, option := range options {
		fmt.Fprintf(&prompt, "  %d. %s", index+1, option.label)
		if option.note != "" {
			fmt.Fprintf(&prompt, " (%s)", option.note)
		}
		prompt.WriteString("\n")
	}
	fmt.Fprintf(&prompt, "Selection [1-%d, q to %s]: ", len(options), quit)
	for {
		if _, err := io.WriteString(a.errOut, prompt.String()); err != nil {
			return 0, err
		}
		answer, err := a.input.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		answer = strings.TrimSpace(answer)
		if answer == "" && errors.Is(err, io.EOF) {
			return 0, errMenuCancelled
		}
		if answer == "" || answer == "q" {
			return 0, errMenuCancelled
		}
		index, convErr := strconv.Atoi(answer)
		if convErr == nil && index >= 1 && index <= len(options) {
			return index - 1, nil
		}
		if _, err := fmt.Fprintf(a.errOut, "Enter a number between 1 and %d.\n", len(options)); err != nil {
			return 0, err
		}
	}
}

func menuDigit(key string) (int, bool) {
	if len(key) != 1 || key[0] < '1' || key[0] > '9' {
		return 0, false
	}
	return int(key[0] - '1'), true
}
