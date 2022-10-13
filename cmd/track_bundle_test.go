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

//go:build unit

package cmd

import (
	"bytes"
	"context"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_TrackBundleCommand(t *testing.T) {
	tempDir := t.TempDir()

	cases := []struct {
		name         string
		args         []string
		outputFile   string
		expectUrls   []string
		expectInput  string
		expectStdout bool
	}{
		{
			name: "simple",
			args: []string{
				"--bundle",
				"registry/image:tag",
			},
			expectUrls:   []string{"registry/image:tag"},
			expectStdout: true,
		},
		{
			name: "with output file",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--output",
				path.Join(tempDir, "output-1.json"),
			},
			outputFile:   path.Join(tempDir, "output-1.json"),
			expectUrls:   []string{"registry/image:tag"},
			expectStdout: false,
		},
		{
			name: "with input file",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				path.Join(tempDir, "input-3.json"),
			},
			expectUrls:   []string{"registry/image:tag"},
			expectInput:  path.Join(tempDir, "input-3.json"),
			expectStdout: true,
		},
		{
			name: "with input file replace",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				path.Join(tempDir, "tracker-3.json"),
				"--replace",
			},
			outputFile:   path.Join(tempDir, "tracker-3.json"),
			expectUrls:   []string{"registry/image:tag"},
			expectInput:  path.Join(tempDir, "tracker-3.json"),
			expectStdout: true,
		},
		{
			name: "with input and output files",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				path.Join(tempDir, "input-4.json"),
				"--output",
				path.Join(tempDir, "output-4.json"),
			},
			outputFile:   path.Join(tempDir, "output-4.json"),
			expectUrls:   []string{"registry/image:tag"},
			expectInput:  path.Join(tempDir, "input-4.json"),
			expectStdout: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.expectInput != "" {
				err := os.WriteFile(c.expectInput, []byte(`{"spam": true}`), 0777)
				assert.NoError(t, err)
			}
			testOutput := `{"test": true}`
			track := func(ctx context.Context, urls []string, input string) ([]byte, error) {
				assert.Equal(t, c.expectUrls, urls)
				assert.Equal(t, c.expectInput, input)
				return []byte(testOutput), nil
			}
			cmd := trackBundleCmd(track)
			cmd.SetArgs(c.args)
			var out bytes.Buffer
			cmd.SetOut(&out)
			err := cmd.Execute()
			assert.NoError(t, err)

			if c.expectStdout {
				assert.JSONEq(t, testOutput, out.String())
			} else {
				assert.Empty(t, out.String())
			}

			if c.outputFile != "" {
				actualOutput, err := ioutil.ReadFile(c.outputFile)
				assert.NoError(t, err)
				assert.JSONEq(t, testOutput, string(actualOutput))
			}
		})
	}

}
