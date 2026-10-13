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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	yaml "github.com/go-openapi/go-yaml/codec"
	"github.com/pmezard/go-difflib/difflib"
	scopedb "github.com/scopedb/goscopedb"
)

func (a *app) readCatalog(path string) (json.RawMessage, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(a.input)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read catalog file: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, usageError("invalid catalog YAML or JSON: " + err.Error())
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, usageError("expected one YAML or JSON document")
	}
	result, err := json.Marshal(value)
	if err != nil {
		return nil, usageError("catalog must contain JSON-compatible YAML: " + err.Error())
	}
	return result, nil
}

func (a *app) writeCatalogOutput(value any, options catalogOptions) error {
	switch options.output {
	case "":
		return nil
	case "-":
		return writeCatalog(a.out, value, options.format)
	default:
		if err := writeResultFile(options.output, options.force, func(w io.Writer) error {
			return writeCatalog(w, value, options.format)
		}); err != nil {
			return err
		}
		_, err := fmt.Fprintf(a.errOut, "Saved to %s.\n", options.output)
		return err
	}
}

func writeCatalog(writer io.Writer, value any, format string) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if format == "yaml" {
		data, err = yaml.FromJSON(data)
		if err != nil {
			return err
		}
	} else {
		data = append(data, '\n')
	}
	_, err = writer.Write(data)
	return err
}

func catalogDiff(resource catalogResource, change scopedb.CatalogResult) (string, error) {
	before, err := yaml.FromJSON(change.Before)
	if err != nil {
		return "", err
	}
	after, err := yaml.FromJSON(change.After)
	if err != nil {
		return "", err
	}
	beforeLines := strings.SplitAfter(string(before), "\n")
	afterLines := strings.SplitAfter(string(after), "\n")
	label := strings.TrimSpace(resource.Kind + " " + resource.Name)
	return difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: beforeLines[:len(beforeLines)-1], B: afterLines[:len(afterLines)-1],
		FromFile: label + " before",
		ToFile:   label + " after", Context: 3,
	})
}
