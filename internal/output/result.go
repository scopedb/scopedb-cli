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
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	scopedb "github.com/scopedb/goscopedb"
)

const (
	FormatTable = "table"
	FormatJSON  = "json"
	FormatJSONL = "jsonl"
	FormatCSV   = "csv"
)

// RenderResult writes a complete statement result in the requested format.
func RenderResult(writer io.Writer, result *scopedb.ResultSet, format string) error {
	if result == nil {
		return fmt.Errorf("result set is nil")
	}
	values, err := result.ToValues()
	if err != nil {
		return fmt.Errorf("decode result rows: %w", err)
	}
	switch format {
	case FormatTable:
		return renderTable(writer, result.Schema, values)
	case FormatJSON:
		return renderJSON(writer, result.Schema, values, false)
	case FormatJSONL:
		return renderJSON(writer, result.Schema, values, true)
	case FormatCSV:
		return renderCSV(writer, result.Schema, values)
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}

func renderTable(writer io.Writer, schema scopedb.Schema, rows [][]scopedb.Value) error {
	t := table.NewWriter()
	t.SetOutputMirror(writer)
	t.SetStyle(table.StyleLight)
	header := make(table.Row, len(schema))
	for index, field := range schema {
		if field == nil {
			return fmt.Errorf("result schema field %d is nil", index)
		}
		header[index] = field.Name
	}
	t.AppendHeader(header)
	for _, values := range rows {
		row := make(table.Row, len(values))
		for index, value := range values {
			row[index] = displayValue(value, "NULL")
		}
		t.AppendRow(row)
	}
	t.Render()
	return nil
}

type namedValue struct {
	name  string
	value any
}

type orderedObject []namedValue

func (o orderedObject) MarshalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for index, item := range o {
		if index > 0 {
			buffer.WriteByte(',')
		}
		name, err := json.Marshal(item.name)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(item.value)
		if err != nil {
			return nil, err
		}
		buffer.Write(name)
		buffer.WriteByte(':')
		buffer.Write(value)
	}
	buffer.WriteByte('}')
	return buffer.Bytes(), nil
}

func renderJSON(writer io.Writer, schema scopedb.Schema, rows [][]scopedb.Value, lines bool) error {
	if err := ensureUniqueColumns(schema); err != nil {
		return err
	}
	objects := make([]orderedObject, 0, len(rows))
	for _, row := range rows {
		object := make(orderedObject, len(schema))
		for index, field := range schema {
			value, err := jsonValue(row[index], field.Type)
			if err != nil {
				return fmt.Errorf("encode column %q: %w", field.Name, err)
			}
			object[index] = namedValue{name: field.Name, value: value}
		}
		objects = append(objects, object)
	}

	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	if lines {
		for _, object := range objects {
			if err := encoder.Encode(object); err != nil {
				return fmt.Errorf("write JSON Lines result: %w", err)
			}
		}
		return nil
	}
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(objects); err != nil {
		return fmt.Errorf("write JSON result: %w", err)
	}
	return nil
}

func renderCSV(writer io.Writer, schema scopedb.Schema, rows [][]scopedb.Value) error {
	csvWriter := csv.NewWriter(writer)
	header := make([]string, len(schema))
	for index, field := range schema {
		if field == nil {
			return fmt.Errorf("result schema field %d is nil", index)
		}
		header[index] = field.Name
	}
	if err := csvWriter.Write(header); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}
	for _, values := range rows {
		row := make([]string, len(values))
		for index, value := range values {
			row[index] = displayValue(value, "")
		}
		if err := csvWriter.Write(row); err != nil {
			return fmt.Errorf("write CSV row: %w", err)
		}
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return fmt.Errorf("flush CSV result: %w", err)
	}
	return nil
}

func ensureUniqueColumns(schema scopedb.Schema) error {
	seen := make(map[string]struct{}, len(schema))
	for index, field := range schema {
		if field == nil {
			return fmt.Errorf("result schema field %d is nil", index)
		}
		if _, exists := seen[field.Name]; exists {
			return fmt.Errorf("JSON output requires unique column names; %q appears more than once", field.Name)
		}
		seen[field.Name] = struct{}{}
	}
	return nil
}

func displayValue(value any, null string) string {
	switch typed := value.(type) {
	case nil:
		return null
	case []byte:
		return "0x" + hex.EncodeToString(typed)
	case time.Time:
		return typed.UTC().Format(time.RFC3339Nano)
	case time.Duration:
		return typed.String()
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case uint64:
		return strconv.FormatUint(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'g', -1, 64)
	default:
		return fmt.Sprint(typed)
	}
}

func jsonValue(value any, dataType scopedb.DataType) (any, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case []byte:
		return "0x" + hex.EncodeToString(typed), nil
	case time.Time:
		return typed.UTC().Format(time.RFC3339Nano), nil
	case time.Duration:
		return typed.String(), nil
	case string:
		if dataType != scopedb.ArrayDataType && dataType != scopedb.ObjectDataType && dataType != scopedb.AnyDataType {
			return typed, nil
		}
		if !json.Valid([]byte(typed)) {
			if dataType == scopedb.AnyDataType {
				return typed, nil
			}
			return nil, fmt.Errorf("invalid embedded JSON")
		}
		decoder := json.NewDecoder(bytes.NewBufferString(typed))
		decoder.UseNumber()
		var decoded any
		if err := decoder.Decode(&decoded); err != nil {
			if dataType == scopedb.AnyDataType {
				return typed, nil
			}
			return nil, fmt.Errorf("invalid embedded JSON: %w", err)
		}
		return decoded, nil
	default:
		return typed, nil
	}
}
