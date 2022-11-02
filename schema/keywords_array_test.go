// Copyright 2022 Red Hat, Inc.
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

package schema

import (
	"context"
	"errors"
	"testing"

	"github.com/qri-io/jsonpointer"
	"github.com/qri-io/jsonschema"
	"github.com/stretchr/testify/assert"
)

var ab = uniqueKeys([]jsonpointer.Pointer{jsonpointer.Pointer([]string{"a"}), jsonpointer.Pointer([]string{"b"})})

func TestUnmarshalJSON(t *testing.T) {
	cases := []struct {
		name     string
		json     string
		expected *uniqueKeys
		err      error
	}{
		{
			name:     "empty array",
			json:     "[]",
			expected: &uniqueKeys{},
		},
		{
			name: "not array",
			json: "{}",
			err:  errors.New("json: cannot unmarshal object into Go value of type []string"),
		},
		{
			name:     "valid JSON Pointers",
			json:     `["/a", "/b"]`,
			expected: &ab,
		},
		{
			name: "invalid JSON Pointers",
			json: `["#!"]`,
			err:  errors.New("non-empty references must begin with a '/' character"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := uniqueKeys{}
			err := u.UnmarshalJSON([]byte(c.json))

			if c.err == nil {
				assert.NoError(t, err)

				assert.Equal(t, c.expected, &u)
			} else {
				assert.EqualError(t, err, c.err.Error())
			}
		})
	}
}

func TestMarshalJSON(t *testing.T) {
	json, err := ab.MarshalJSON()
	assert.NoError(t, err)
	assert.JSONEq(t, `["/a", "/b"]`, string(json))
}

func TestValidateKeyword(t *testing.T) {
	data1 := []any{
		map[string]any{"a": 1},
		map[string]any{"b": 1},
		map[string]any{"a": 1},
	}

	data2 := []any{
		map[string]any{"c": 1},
		map[string]any{"c": 1},
		map[string]any{"c": 1},
	}

	cases := []struct {
		name       string
		uniqueKeys uniqueKeys
		data       any
		expected   []jsonschema.KeyError
	}{
		{
			name:     "no data",
			data:     nil,
			expected: []jsonschema.KeyError{},
		},
		{
			name:     "non array",
			data:     []string{},
			expected: []jsonschema.KeyError{},
		},
		{
			name:       "non unique",
			uniqueKeys: ab,
			data:       data1,
			expected: []jsonschema.KeyError{
				{
					PropertyPath: "/",
					InvalidValue: data1,
					Message:      `found non unique value for JSON paths [/a /b]: {"a":1}`,
				},
			},
		},
		{
			name:       "unique",
			uniqueKeys: ab,
			data:       data2,
			expected:   []jsonschema.KeyError{},
		},
	}

	cases = cases[3:4]

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := jsonschema.NewValidationState(&slsa_provenance_v0_2)
			c.uniqueKeys.ValidateKeyword(context.Background(), state, c.data)

			assert.Equal(t, c.expected, *state.Errs)
		})

	}
}
