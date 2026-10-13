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
)

func catalogNames(resource catalogResource, kind string, definition json.RawMessage) ([]string, error) {
	// Decode only the hierarchy and names; columns and other definition fields are skipped.
	type entry struct {
		Name      string  `json:"name"`
		Databases []entry `json:"databases"`
		Schemas   []entry `json:"schemas"`
		Tables    []entry `json:"tables"`
		Views     []entry `json:"views"`
	}
	var document entry
	if err := json.Unmarshal(definition, &document); err != nil {
		return nil, fmt.Errorf("invalid catalog response: %w", err)
	}
	names, err := resource.names()
	if err != nil {
		return nil, err
	}
	databases := document.Databases
	switch resource.Kind {
	case "database":
		databases = []entry{document}
	case "schema":
		databases = []entry{{Name: names[0], Schemas: []entry{document}}}
	}
	result := []string{}
	for _, database := range databases {
		if kind == "databases" {
			result = append(result, formatCatalogName(database.Name))
			continue
		}
		for _, schema := range database.Schemas {
			if kind == "schemas" {
				result = append(result, formatCatalogName(database.Name, schema.Name))
				continue
			}
			objects := schema.Tables
			if kind == "views" {
				objects = schema.Views
			}
			for _, object := range objects {
				result = append(result, formatCatalogName(database.Name, schema.Name, object.Name))
			}
		}
	}
	return result, nil
}
