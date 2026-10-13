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
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type catalogResource struct {
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
}

func (r catalogResource) segments() ([]string, error) {
	var count int
	switch r.Kind {
	case "catalog":
		count = 0
	case "database":
		count = 1
	case "schema":
		count = 2
	case "table", "view":
		count = 3
	default:
		return nil, usageError("resource must be catalog, database, schema, table, or view")
	}
	names, err := parseCatalogName(r.Name)
	if err != nil {
		return nil, err
	}
	if len(names) != count {
		return nil, usageError(fmt.Sprintf("%s requires %d name component(s)", r.Kind, count))
	}
	var segments []string
	for i, name := range names {
		if i == 0 {
			segments = append(segments, "databases")
		}
		if i == 1 {
			segments = append(segments, "schemas")
		}
		if i == 2 {
			collection := "tables"
			if r.Kind == "view" {
				collection = "views"
			}
			segments = append(segments, collection)
		}
		segments = append(segments, name)
	}
	return segments, nil
}

func (r catalogResource) validateList(kind string) error {
	switch kind {
	case "databases", "schemas", "tables", "views":
	default:
		return usageError("list requires databases, schemas, tables, or views")
	}
	switch r.Kind {
	case "catalog":
		return nil
	case "database":
		if kind != "databases" {
			return nil
		}
	case "schema":
		if kind == "tables" || kind == "views" {
			return nil
		}
	}
	return usageError("cannot list " + kind + " within a " + r.Kind)
}

func formatCatalogName(names ...string) string {
	parts := make([]string, 0, len(names))
	for _, name := range names {
		quote := name == "" || strings.ToLower(name) != name
		for i, ch := range name {
			if ch != '_' && !unicode.IsLetter(ch) && (i == 0 || !unicode.IsDigit(ch)) {
				quote = true
				break
			}
		}
		if quote {
			name = "`" + strings.ReplaceAll(strings.ReplaceAll(name, "\\", "\\\\"), "`", "``") + "`"
		}
		parts = append(parts, name)
	}
	return strings.Join(parts, ".")
}

// Bare names are case insensitive; backticks preserve case and support escapes.
func parseCatalogName(input string) ([]string, error) {
	remaining := strings.TrimSpace(input)
	var names []string
	for remaining != "" {
		var name string
		if remaining[0] == '`' {
			remaining = remaining[1:]
			var part strings.Builder
			closed := false
			for len(remaining) > 0 {
				if remaining[0] == '\\' {
					if len(remaining) > 1 && (remaining[1] == '`' || remaining[1] == '\'') {
						part.WriteByte(remaining[1])
						remaining = remaining[2:]
						continue
					}
					ch, _, tail, err := strconv.UnquoteChar(remaining, '"')
					if err != nil {
						return nil, usageError("invalid escape in resource name")
					}
					part.WriteRune(ch)
					remaining = tail
					continue
				}

				if remaining[0] != '`' {
					part.WriteByte(remaining[0])
					remaining = remaining[1:]
					continue
				}
				remaining = remaining[1:]
				if strings.HasPrefix(remaining, "`") {
					part.WriteByte('`')
					remaining = remaining[1:]
					continue
				}
				closed = true
				break
			}
			if !closed {
				return nil, usageError("unclosed backtick in resource name")
			}
			name = part.String()
		} else {
			end := strings.IndexByte(remaining, '.')
			if end < 0 {
				end = len(remaining)
			}
			name = strings.TrimSpace(remaining[:end])
			remaining = remaining[end:]
			for i, ch := range name {
				if ch != '_' && !unicode.IsLetter(ch) && (i == 0 || !unicode.IsDigit(ch)) {
					return nil, usageError("quote special resource names with backticks")
				}
			}
			name = strings.ToLower(name)
		}
		if name == "" || strings.ContainsRune(name, '\x00') {
			return nil, usageError("empty resource names must be managed through their parent definition")
		}
		names = append(names, name)
		remaining = strings.TrimSpace(remaining)
		if remaining == "" {
			break
		}
		if remaining[0] != '.' {
			return nil, usageError("resource name components must be separated by dots")
		}
		remaining = strings.TrimSpace(remaining[1:])
		if remaining == "" {
			return nil, usageError("resource name must not end with a dot")
		}
	}
	return names, nil
}
