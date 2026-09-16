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
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
)

const (
	structuredFormatTable = "table"
	structuredFormatJSON  = "json"
)

func validateStructuredFormat(value string) error {
	if value != structuredFormatTable && value != structuredFormatJSON {
		return usageError(fmt.Sprintf("unsupported format %q; use table or json", value))
	}
	return nil
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func newTable(writer io.Writer, header ...any) table.Writer {
	result := table.NewWriter()
	result.SetOutputMirror(writer)
	result.SetStyle(table.StyleLight)
	if len(header) > 0 {
		result.AppendHeader(table.Row(header))
	}
	return result
}

func optionalTime(value *time.Time) string {
	if value == nil {
		return "-"
	}
	return value.UTC().Format(time.RFC3339)
}

func joinTags(tags []string) string {
	if len(tags) == 0 {
		return "-"
	}
	return strings.Join(tags, ",")
}
