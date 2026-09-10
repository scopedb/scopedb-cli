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
	"context"
	"strings"
	"testing"
)

func TestRootVersionFlag(t *testing.T) {
	var stdout bytes.Buffer
	command := NewRoot(Dependencies{Out: &stdout})
	command.SetArgs([]string{"--version"})

	if err := command.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext() error = %v", err)
	}
	if output := stdout.String(); !strings.HasPrefix(output, "scope ") || !strings.HasSuffix(output, "\n") {
		t.Errorf("version output = %q", output)
	}
}
