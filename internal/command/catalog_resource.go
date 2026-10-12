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
	"net/http"
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
	case "databases":
		count = 0
	case "database", "schemas":
		count = 1
	case "schema", "tables", "views":
		count = 2
	case "table", "view":
		count = 3
	default:
		return nil, usageError("resource must be databases, database, schemas, schema, tables, table, views, or view")
	}
	names, err := parseCatalogName(r.Name)
	if err != nil {
		return nil, err
	}
	if len(names) != count {
		return nil, usageError(fmt.Sprintf("%s requires %d name component(s)", r.Kind, count))
	}
	segments := []string{"databases"}
	for i, name := range names {
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
	if r.Kind == "schemas" || r.Kind == "tables" || r.Kind == "views" {
		segments = append(segments, r.Kind)
	}
	return segments, nil
}

func (r catalogResource) drop() (string, json.RawMessage) {
	switch r.Kind {
	case "databases", "schemas", "tables", "views":
		return http.MethodPut, json.RawMessage(fmt.Sprintf(`{"%s":[]}`, r.Kind))
	default:
		return http.MethodDelete, nil
	}
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
			return nil, usageError("empty resource names must be managed through their parent collection")
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
