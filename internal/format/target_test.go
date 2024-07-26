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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unit

package format

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTargetParser(t *testing.T) {
	defaultFormat := "default"
	defaultPath := "default.out"
	defaultOptions := Options{
		ShowSuccesses: false,
	}

	cases := []struct {
		name            string
		expectedFormat  string
		expectedPath    string
		expectedOptions Options
		targetName      string
	}{
		{name: "all defaults", expectedFormat: defaultFormat, expectedOptions: defaultOptions},
		{name: "format", expectedFormat: "spam", expectedOptions: defaultOptions, targetName: "spam"},
		{name: "format no file", expectedFormat: "spam", expectedOptions: defaultOptions, targetName: "spam="},
		{name: "format and file", expectedFormat: "spam", expectedOptions: defaultOptions, targetName: "spam=spam.out", expectedPath: "spam.out"},
		{name: "format and option", expectedFormat: "spam", expectedOptions: Options{ShowSuccesses: true}, targetName: "spam?show-successes=true"},
		{name: "format no file with option", expectedFormat: "spam", expectedOptions: Options{ShowSuccesses: true}, targetName: "spam=?show-successes=true"},
		{name: "format with file and option", expectedFormat: "spam", expectedOptions: Options{ShowSuccesses: true}, targetName: "spam=spam.out?show-successes=true", expectedPath: "spam.out"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			defaultWriter := fileWriter{path: defaultPath, fs: fs}
			parser := NewTargetParser(defaultFormat, defaultOptions, defaultWriter, fs)
			target, err := parser.Parse(c.targetName)
			require.NoError(t, err)

			assert.Equal(t, c.expectedFormat, target.Format)
			if c.expectedPath == "" {
				assert.Equal(t, defaultWriter, target.writer)
			} else {
				assert.Equal(t, c.expectedPath, target.writer.(*fileWriter).path)
			}

			assert.Equal(t, c.expectedOptions, target.Options)
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
