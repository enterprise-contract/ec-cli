// Copyright The Enterprise Contract Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unit

package msa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_MapGet(t *testing.T) {
	jsonInput := `{
		"foo": "bar",
		"baz": true,
		"quux": 99,
		"fizz": [
			"buzz",
			"pop"
		],
		"zap": {
			"zip": "zup"
		}
	}`

	data, err := FromJSON(jsonInput)
	assert.NoError(t, err)

	t.Run("to map", func(t *testing.T) {
		val := data.ToMap()
		assert.IsType(t, map[string]any{}, val)
		assert.Equal(t, "bar", val["foo"])
	})

	t.Run("to json", func(t *testing.T) {
		val := data.ToJSONStr()
		assert.JSONEq(t, jsonInput, val)
		assert.Contains(t, val, "\"foo\":\"bar\",\"")

		val = data.ToJSONIndentStr("  ")
		assert.JSONEq(t, jsonInput, val)
		assert.Contains(t, val, "\n  \"foo\": \"bar\",\n")
	})

	t.Run("get string", func(t *testing.T) {
		val, err := data.GetStr("foo")
		assert.Equal(t, "bar", val)
		assert.NoError(t, err)
	})

	t.Run("get bool", func(t *testing.T) {
		val, err := data.GetBool("baz")
		assert.Equal(t, true, val)
		assert.NoError(t, err)
	})

	t.Run("get num", func(t *testing.T) {
		val, err := data.GetNum("quux")
		assert.Equal(t, float64(99), val)
		assert.NoError(t, err)
	})

	t.Run("get slice", func(t *testing.T) {
		val, err := data.GetSlice("fizz")
		assert.Equal(t, []any{"buzz", "pop"}, val)
		assert.NoError(t, err)
	})

	t.Run("get map", func(t *testing.T) {
		val, err := data.GetMap("zap")
		assert.Equal(t, map[string]any{"zip": "zup"}, val)
		assert.NoError(t, err)
	})

	t.Run("get msa", func(t *testing.T) {
		val, err := data.GetMSA("zap")
		assert.Equal(t, MapStringAny{"zip": "zup"}, val)
		assert.NoError(t, err)
	})

	t.Run("get with bad key", func(t *testing.T) {
		_, err := data.GetStr("fooo")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "Key 'fooo' not found in")
	})

	t.Run("get with wrong type", func(t *testing.T) {
		_, err := data.GetNum("foo")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "Unexpected type string for key 'foo' in")

		_, err = data.GetStr("baz")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "Unexpected type bool for key 'baz' in")
	})

	t.Run("clone", func(t *testing.T) {
		c := data.Clone()
		assert.JSONEq(t, jsonInput, c.ToJSONStr())
	})

	t.Run("unexpected mutation", func(t *testing.T) {
		a, err := FromJSON(jsonInput)
		assert.NoError(t, err)
		b := a.ToMap()

		// Modify b
		b["foo"] = "hey"

		// Notice that a was mutated, which might be unexpected
		assert.Equal(t, "hey", a["foo"])
	})

	t.Run("using clone to avoid unexpected mutation", func(t *testing.T) {
		a, err := FromJSON(jsonInput)
		assert.NoError(t, err)
		b := a.Clone().ToMap()

		// Modify b
		b["foo"] = "hey"

		// This time a was not mutated
		assert.Equal(t, "bar", a["foo"])
	})
}
