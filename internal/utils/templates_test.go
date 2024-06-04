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

package utils

import (
	"bytes"
	"embed"
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed test_templates/*.template
var testTemplatesFS embed.FS

func TestTemplateRender(t *testing.T) {
	tests := []struct {
		expected string
		input    map[string]string
	}{
		{
			input:    map[string]string{"name": "world"},
			expected: "✓ Hello and greetings, world.\n\n",
		},
	}
	for _, tt := range tests {
		output, err := RenderFromTemplates(tt.input, testTemplatesFS)
		assert.NoError(t, err)
		assert.Equal(t, tt.expected, string(output))
	}
}

func TestSetupTemplate(t *testing.T) {
	tmpl, err := SetupTemplate(testTemplatesFS)
	assert.NoError(t, err)

	tests := []struct {
		main     string
		expected string
		input    map[string]string
	}{
		{
			input:    map[string]string{"name": "friend"},
			expected: "✓ Hello and greetings, friend.\n\n",
		},
		{
			main:     "main.template",
			expected: "✓ Hello and greetings, spam.\n\n",
			input:    map[string]string{"name": "spam"},
		},
		{
			main:     "_name.template",
			expected: "and hola, amigo.\n",
			input:    map[string]string{"greeting": "hola", "name": "amigo"},
		},
	}
	for _, tt := range tests {
		var buf bytes.Buffer
		var err error
		if tt.main == "" {
			err = tmpl.Execute(&buf, tt.input)
			assert.NoError(t, err)
		} else {
			err = tmpl.ExecuteTemplate(&buf, tt.main, tt.input)
			assert.NoError(t, err)
		}
		assert.Equal(t, tt.expected, buf.String())
	}
}
