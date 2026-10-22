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

package output

import (
	"fmt"
	"io"

	"github.com/jedib0t/go-pretty/v6/table"
)

func NewTable(header ...any) table.Writer {
	result := table.NewWriter()
	result.SetStyle(table.StyleLight)
	if len(header) > 0 {
		result.AppendHeader(table.Row(header))
	}
	return result
}

func WriteTable(writer io.Writer, t table.Writer) error {
	text := t.Render()
	if text == "" {
		return nil
	}
	// SetOutputMirror discards write errors, so write the rendered table explicitly.
	_, err := fmt.Fprintln(writer, text)
	return err
}
