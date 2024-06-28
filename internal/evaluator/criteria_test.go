package evaluator

import (
	"testing"

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
