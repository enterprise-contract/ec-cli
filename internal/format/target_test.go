// Copyright Red Hat.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestTargetParser(t *testing.T) {
	defaultFormat := "default"
	defaultPath := "default.out"
	cases := []struct {
		name                string
		expectFormat        string
		expectDefaultWriter bool
		targetName          string
	}{
		{name: "all defaults", expectFormat: defaultFormat, expectDefaultWriter: true},
		{name: "all defaults", expectFormat: "spam", targetName: "spam", expectDefaultWriter: true},
		{name: "all defaults", expectFormat: "spam", targetName: "spam=", expectDefaultWriter: true},
		{name: "all defaults", expectFormat: "spam", targetName: "spam=spam.out"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			defaultWriter := fileWriter{path: defaultPath, fs: fs}
			parser := NewTargetParser(defaultFormat, defaultWriter, fs)
			target := parser.Parse(c.targetName)

			assert.Equal(t, target.Format, c.expectFormat)
			if c.expectDefaultWriter {
				assert.Equal(t, target.writer, defaultWriter)
			} else {
				assert.NotEqual(t, target.writer, defaultWriter)
			}
		})
	}
}

func TestSimpleFileWriter(t *testing.T) {
	fs := afero.NewMemMapFs()
	writer := fileWriter{path: "out", fs: fs}
	_, err := writer.Write([]byte("spam"))
	assert.NoError(t, err)
	actual, err := afero.ReadFile(fs, "out")
	assert.NoError(t, err)
	assert.Equal(t, "spam", string(actual))
}
