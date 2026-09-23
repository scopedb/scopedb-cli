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

import "golang.org/x/sys/windows"

func hideTerminalInput(fd int) (func() error, error) {
	handle := windows.Handle(fd)
	var previous uint32
	if err := windows.GetConsoleMode(handle, &previous); err != nil {
		return nil, err
	}
	if err := windows.SetConsoleMode(handle, previous&^windows.ENABLE_ECHO_INPUT); err != nil {
		return nil, err
	}
	return func() error { return windows.SetConsoleMode(handle, previous) }, nil
}
