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
	"embed"
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed test_templates/*.tmpl
var testTemplatesFS embed.FS

func TestTemplateRender(t *testing.T) {
	input := map[string]any{
		"name": "spam world",
	}
	output, err := RenderFromTemplates(input, testTemplatesFS)
	assert.NoError(t, err)
	assert.Equal(t, "✓ Hello and bonjour, spam world.\n\n", string(output))
}
