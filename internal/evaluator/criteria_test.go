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

package evaluator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLen(t *testing.T) {
	tests := []struct {
		name        string
		criteria    *Criteria
		expectedLen int
	}{
		{
			name: "Empty Criteria",
			criteria: &Criteria{
				digestItems:  map[string][]string{},
				defaultItems: []string{},
			},
			expectedLen: 0,
		},
		{
			name: "Only Default Items",
			criteria: &Criteria{
				digestItems:  map[string][]string{},
				defaultItems: []string{"default1", "default2"},
			},
			expectedLen: 2,
		},
		{
			name: "Only Digest Items",
			criteria: &Criteria{
				digestItems: map[string][]string{
					"key1": {"value1", "value2"},
					"key2": {"value3"},
				},
				defaultItems: []string{},
			},
			expectedLen: 3,
		},
		{
			name: "Both Default and Digest Items",
			criteria: &Criteria{
				digestItems: map[string][]string{
					"key1": {"value1", "value2"},
					"key2": {"value3"},
				},
				defaultItems: []string{"default1", "default2"},
			},
			expectedLen: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.criteria.len(); got != tt.expectedLen {
				t.Errorf("Criteria.len() = %d, want %d", got, tt.expectedLen)
			}
		})
	}
}

func TestAddItem(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		initial  *Criteria
		expected *Criteria
	}{
		{
			name:  "Add to defaultItems",
			key:   "",
			value: "defaultValue",
			initial: &Criteria{
				defaultItems: []string{},
				digestItems:  make(map[string][]string),
			},
			expected: &Criteria{
				defaultItems: []string{"defaultValue"},
				digestItems:  make(map[string][]string),
			},
		},
		{
			name:  "Add to digestItems",
			key:   "key1",
			value: "digestValue1",
			initial: &Criteria{
				defaultItems: []string{},
				digestItems:  make(map[string][]string),
			},
			expected: &Criteria{
				defaultItems: []string{},
				digestItems: map[string][]string{
					"key1": {"digestValue1"},
				},
			},
		},
		{
			name:  "Add to existing digestItems",
			key:   "key1",
			value: "digestValue2",
			initial: &Criteria{
				defaultItems: []string{},
				digestItems: map[string][]string{
					"key1": {"digestValue1"},
				},
			},
			expected: &Criteria{
				defaultItems: []string{},
				digestItems: map[string][]string{
					"key1": {"digestValue1", "digestValue2"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.initial.addItem(tt.key, tt.value)
			require.Equal(t, tt.initial, tt.expected)
		})
	}
}

func TestAddArray(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		values   []string
		initial  *Criteria
		expected *Criteria
	}{
		{
			name:   "Add to defaultItems",
			key:    "",
			values: []string{"defaultValue1", "defaultValue2"},
			initial: &Criteria{
				defaultItems: []string{},
				digestItems:  make(map[string][]string),
			},
			expected: &Criteria{
				defaultItems: []string{"defaultValue1", "defaultValue2"},
				digestItems:  make(map[string][]string),
			},
		},
		{
			name:   "Add to digestItems",
			key:    "key1",
			values: []string{"digestValue1", "digestValue2"},
			initial: &Criteria{
				defaultItems: []string{},
				digestItems:  make(map[string][]string),
			},
			expected: &Criteria{
				defaultItems: []string{},
				digestItems: map[string][]string{
					"key1": {"digestValue1", "digestValue2"},
				},
			},
		},
		{
			name:   "Add to existing digestItems",
			key:    "key1",
			values: []string{"digestValue2", "digestValue3"},
			initial: &Criteria{
				defaultItems: []string{},
				digestItems: map[string][]string{
					"key1": {"digestValue1"},
				},
			},
			expected: &Criteria{
				defaultItems: []string{},
				digestItems: map[string][]string{
					"key1": {"digestValue1", "digestValue2", "digestValue3"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.initial.addArray(tt.key, tt.values)
			require.Equal(t, tt.initial, tt.expected)
		})
	}
}

func TestGet(t *testing.T) {
	c := &Criteria{
		digestItems: map[string][]string{
			"quay.io/test/ec-test": {"item"},
			"sha256:2c5e3b2f1e2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c": {"item-digest"},
		},
		defaultItems: []string{"default1", "default2"},
	}
	tests := []struct {
		name     string
		key      string
		expected []string
	}{
		{
			name:     "test with image ref",
			key:      "quay.io/test/ec-test",
			expected: []string{"item", "default1", "default2"},
		},
		{
			name:     "test with image ref and tag",
			key:      "quay.io/test/ec-test:latest",
			expected: []string{"item", "default1", "default2"},
		},
		{
			name:     "test with image digest",
			key:      "quay.io/test/ec@sha256:2c5e3b2f1e2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c",
			expected: []string{"item-digest", "default1", "default2"},
		},
		{
			name:     "test key doesn't exist",
			key:      "unknown",
			expected: []string{"default1", "default2"},
		},
		{
			name:     "test with image and bad digest",
			key:      "quay.io/test/ec-test@sha256:2c5e3b2f1e2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d",
			expected: []string{"default1", "default2"},
		},
		{
			name:     "test with image not set",
			expected: []string{"default1", "default2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, c.get(tt.key))
		})
	}
}
