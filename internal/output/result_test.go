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
	"strings"
	"testing"
	"time"

	scopedb "github.com/scopedb/goscopedb"
)

func TestRenderJSONPreservesColumnOrderAndTypes(t *testing.T) {
	schema := scopedb.Schema{
		&scopedb.FieldSchema{Name: "id", Type: scopedb.UIntDataType},
		&scopedb.FieldSchema{Name: "payload", Type: scopedb.ObjectDataType},
		&scopedb.FieldSchema{Name: "created", Type: scopedb.TimestampDataType},
		&scopedb.FieldSchema{Name: "bytes", Type: scopedb.BinaryDataType},
	}
	rows := [][]scopedb.Value{{
		uint64(42),
		`{"ready":true}`,
		time.Date(2026, 9, 9, 1, 2, 3, 4, time.FixedZone("offset", 3600)),
		[]byte{0xde, 0xad},
	}}
	var output bytes.Buffer
	if err := renderJSON(&output, schema, rows, false); err != nil {
		t.Fatalf("renderJSON() error = %v", err)
	}
	want := "[\n  {\n    \"id\": 42,\n    \"payload\": {\n      \"ready\": true\n    },\n    \"created\": \"2026-09-09T00:02:03.000000004Z\",\n    \"bytes\": \"0xdead\"\n  }\n]\n"
	if got := output.String(); got != want {
		t.Errorf("JSON output:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderCSVAndTableNulls(t *testing.T) {
	schema := scopedb.Schema{
		&scopedb.FieldSchema{Name: "name", Type: scopedb.StringDataType},
		&scopedb.FieldSchema{Name: "value", Type: scopedb.IntDataType},
	}
	rows := [][]scopedb.Value{{"alpha", nil}}
	var csvOutput bytes.Buffer
	if err := renderCSV(&csvOutput, schema, rows); err != nil {
		t.Fatalf("renderCSV() error = %v", err)
	}
	if got, want := csvOutput.String(), "name,value\nalpha,\n"; got != want {
		t.Errorf("CSV = %q, want %q", got, want)
	}
	var tableOutput bytes.Buffer
	if err := renderTable(&tableOutput, schema, rows); err != nil {
		t.Fatalf("renderTable() error = %v", err)
	}
	if !strings.Contains(tableOutput.String(), "NULL") || !strings.Contains(tableOutput.String(), "alpha") {
		t.Errorf("table output = %q", tableOutput.String())
	}
}

func TestRenderJSONRejectsDuplicateColumns(t *testing.T) {
	schema := scopedb.Schema{
		&scopedb.FieldSchema{Name: "value", Type: scopedb.IntDataType},
		&scopedb.FieldSchema{Name: "value", Type: scopedb.IntDataType},
	}
	err := renderJSON(&bytes.Buffer{}, schema, [][]scopedb.Value{{int64(1), int64(2)}}, false)
	if err == nil || !strings.Contains(err.Error(), "unique column names") {
		t.Fatalf("renderJSON() error = %v", err)
	}
}
