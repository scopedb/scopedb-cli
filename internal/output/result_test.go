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
	"testing"
	"time"

	scopedb "github.com/scopedb/goscopedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, renderJSON(&output, schema, rows, false))
	want := "[\n  {\n    \"id\": 42,\n    \"payload\": {\n      \"ready\": true\n    },\n    \"created\": \"2026-09-09T00:02:03.000000004Z\",\n    \"bytes\": \"0xdead\"\n  }\n]\n"
	assert.Equal(t, want, output.String())
}

func TestRenderCSVAndTableNulls(t *testing.T) {
	schema := scopedb.Schema{
		&scopedb.FieldSchema{Name: "name", Type: scopedb.StringDataType},
		&scopedb.FieldSchema{Name: "value", Type: scopedb.IntDataType},
	}
	rows := [][]scopedb.Value{{"alpha", nil}}
	var csvOutput bytes.Buffer
	require.NoError(t, renderCSV(&csvOutput, schema, rows))
	assert.Equal(t, "name,value\nalpha,\n", csvOutput.String())

	var tableOutput bytes.Buffer
	require.NoError(t, renderTable(&tableOutput, schema, rows))
	assert.Contains(t, tableOutput.String(), "NULL")
	assert.Contains(t, tableOutput.String(), "alpha")
}

func TestRenderJSONRejectsDuplicateColumns(t *testing.T) {
	schema := scopedb.Schema{
		&scopedb.FieldSchema{Name: "value", Type: scopedb.IntDataType},
		&scopedb.FieldSchema{Name: "value", Type: scopedb.IntDataType},
	}
	err := renderJSON(&bytes.Buffer{}, schema, [][]scopedb.Value{{int64(1), int64(2)}}, false)
	assert.ErrorContains(t, err, "unique column names")
}
