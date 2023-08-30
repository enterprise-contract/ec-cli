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

// Not sure if this is idiomatic go, but I'm trying to make it easier
// to work with untyped maps such as might be created by unmarshalling
// arbitrary JSON data

// Short for MapStringAny
package msa

import (
	"encoding/json"
	"fmt"
)

type MapStringAny map[string]any

// Create a MapStringAny from a plain map[string]any
func FromMap(m map[string]any) MapStringAny {
	return MapStringAny(m)
}

// Create a MapStringAny by unmarshaling json bytes
func FromJSONBytes(bytes []byte) (MapStringAny, error) {
	var m MapStringAny
	err := json.Unmarshal(bytes, &m)
	return m, err
}

// Create a MapStringAny by unmarshaling a json string
func FromJSON(str string) (MapStringAny, error) {
	return FromJSONBytes([]byte(str))
}

// Convert back to a plain map[string]any
func (m MapStringAny) ToMap() map[string]any {
	return map[string]any(m)
}

// Marshal to json bytes
func (m MapStringAny) ToJSON() []byte {
	result, err := json.Marshal(m)
	if err != nil {
		// Since we're generally creating MapStringAny objects from
		// valid JSON and error here should be unlikely. For convenience
		// let's not force the caller to declare and handle an error every
		// time this is called.
		panic(fmt.Errorf("Unexpected marshaling problem: %w", err))
	}
	return result
}

func (m MapStringAny) ToJSONStr() string {
	return string(m.ToJSON())
}

// Marshal to formatted json bytes with indenting
func (m MapStringAny) ToJSONIndent(indent string) []byte {
	result, err := json.MarshalIndent(m, "", indent)
	if err != nil {
		// (The comment in the ToJSON method above applies here too)
		panic(fmt.Errorf("Unexpected marshaling problem: %w", err))
	}
	return result
}

func (m MapStringAny) ToJSONIndentStr(indent string) string {
	return string(m.ToJSONIndent(indent))
}

// Get a string value from a map with string keys
func (m MapStringAny) GetStr(key string) (string, error) {
	return mapGet[string](m, key)
}

// Get a bool value from a map with string keys
func (m MapStringAny) GetBool(key string) (bool, error) {
	return mapGet[bool](m, key)
}

// Get a float64 value from a map with string keys
// (You might expect it to be an int, but a float64 is what
// the JSON decoder creates for a number.)
func (m MapStringAny) GetNum(key string) (float64, error) {
	return mapGet[float64](m, key)
}

// Get a slice from a map with string keys
func (m MapStringAny) GetSlice(key string) ([]any, error) {
	return mapGet[[]any](m, key)
}

// Get a map from a map with string keys
func (m MapStringAny) GetMap(key string) (map[string]any, error) {
	return mapGet[map[string]any](m, key)
}

// Get a MapStringAny from a map with string keys
func (m MapStringAny) GetMSA(key string) (MapStringAny, error) {
	result, err := m.GetMap(key)
	if err != nil {
		return nil, err
	}
	return FromMap(result), nil
}

// IIUC you can't use generics in a method, so that's why this one is a plain function instead of a method.
func mapGet[T string | bool | float64 | []any | map[string]any](m MapStringAny, key string) (T, error) {
	var (
		rawVal any
		ok     bool
		result T
	)

	if rawVal, ok = m[key]; !ok {
		return result, fmt.Errorf("Key '%s' not found in %v", key, m)
	}

	if result, ok = rawVal.(T); !ok {
		return result, fmt.Errorf("Unexpected type %T for key '%s' in %v", rawVal, key, m)
	}

	return result, nil
}
