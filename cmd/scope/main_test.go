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

package main

import (
	"context"
	"testing"

	"github.com/scopedb/scopedb-cli/internal/clierror"
	"github.com/scopedb/scopedb-cli/internal/command"
	"github.com/scopedb/scopedb-cli/internal/dataplane"
	"github.com/stretchr/testify/require"
)

func TestRenderError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "reports failures",
			err:  clierror.New(clierror.ExitUsage, "unknown flag: --nope"),
			want: "Error: unknown flag: --nope\n",
		},
		{
			name: "keeps cancellation silent",
			err:  command.NormalizeError(context.Canceled),
			want: "\n",
		},
		{
			name: "keeps statement cancellation silent",
			err:  command.NormalizeError(&dataplane.InterruptedError{StatementID: "stmt-1"}),
			want: "\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, renderError(test.err))
		})
	}
}
