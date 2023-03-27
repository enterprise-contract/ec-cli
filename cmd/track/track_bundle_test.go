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

package track

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/enterprise-contract/ec-cli/internal/utils"
)

func Test_TrackBundleCommand(t *testing.T) {
	cases := []struct {
		name              string
		args              []string
		expectOutput      string
		expectUrls        []string
		expectPrune       bool
		expectInput       string
		expectStdout      bool
		expectImageOutput bool
	}{
		{
			name: "simple",
			args: []string{
				"--bundle",
				"registry/image:tag",
			},
			expectPrune:  true,
			expectUrls:   []string{"registry/image:tag"},
			expectStdout: true,
		},
		{
			name: "with output file",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--output",
				"output-1.json",
			},
			expectOutput: "output-1.json",
			expectUrls:   []string{"registry/image:tag"},
			expectPrune:  true,
			expectStdout: false,
		},
		{
			name: "with input file",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				"input-3.json",
			},
			expectUrls:   []string{"registry/image:tag"},
			expectPrune:  true,
			expectInput:  "input-3.json",
			expectStdout: true,
		},
		{
			name: "with input file replace",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				"tracker-3.json",
				"--replace",
			},
			expectOutput: "tracker-3.json",
			expectUrls:   []string{"registry/image:tag"},
			expectPrune:  true,
			expectInput:  "tracker-3.json",
			expectStdout: true,
		},
		{
			name: "with input and output files",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				"input-4.json",
				"--output",
				"output-4.json",
			},
			expectOutput: "output-4.json",
			expectUrls:   []string{"registry/image:tag"},
			expectPrune:  true,
			expectInput:  "input-4.json",
			expectStdout: false,
		},
		{
			name: "with explicit prune",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--prune",
			},
			expectUrls:   []string{"registry/image:tag"},
			expectPrune:  true,
			expectStdout: true,
		},
		{
			name: "without prune",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--prune=false",
			},
			expectUrls:   []string{"registry/image:tag"},
			expectPrune:  false,
			expectStdout: true,
		},
		{
			name: "using OCI",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				"oci:registry.io/repository/image:tag",
				"--output",
				"oci:registry.io/repository/image:new_tag",
			},
			expectInput:       "registry.io/repository/image:tag",
			expectOutput:      "registry.io/repository/image:new_tag",
			expectPrune:       true,
			expectUrls:        []string{"registry/image:tag"},
			expectStdout:      false,
			expectImageOutput: true,
		},
		{
			name: "using OCI for pull",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				"oci:registry.io/repository/image:tag",
			},
			expectInput:       "registry.io/repository/image:tag",
			expectPrune:       true,
			expectUrls:        []string{"registry/image:tag"},
			expectStdout:      true,
			expectImageOutput: true,
		},
		{
			name: "using OCI for push",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				"input-5.json",
				"--output",
				"oci:registry.io/repository/image:tag",
			},
			expectInput:       "input-5.json",
			expectPrune:       true,
			expectUrls:        []string{"registry/image:tag"},
			expectOutput:      "registry.io/repository/image:tag",
			expectStdout:      false,
			expectImageOutput: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			ctx := utils.WithFS(context.TODO(), fs)
			inputData := []byte(fmt.Sprintf(`{"file": "%s"}`, c.expectInput))

			if c.expectInput != "" {
				err := afero.WriteFile(fs, c.expectInput, inputData, 0777)
				assert.NoError(t, err)
			}
			testOutput := `{"test": true}`
			track := func(_ context.Context, urls []string, input []byte, prune bool) ([]byte, error) {
				assert.Equal(t, c.expectUrls, urls)
				if c.expectInput != "" {
					assert.Equal(t, inputData, input)
				}
				assert.Equal(t, c.expectPrune, prune)
				return []byte(testOutput), nil
			}
			pullImage := func(_ context.Context, imageRef string) ([]byte, error) {
				assert.Equal(t, c.expectInput, imageRef)
				return inputData, nil
			}
			pushImage := func(_ context.Context, imageRef string, data []byte, invocation string) error {
				assert.Equal(t, c.expectOutput, imageRef)
				assert.Equal(t, testOutput, string(data))
				assert.NotEmpty(t, invocation) // in tests this will be the cmd.test in temp directory, counting on os.Args to be correct when ec-cli is invoked
				return nil
			}
			cmd := trackBundleCmd(track, pullImage, pushImage)
			cmd.SetContext(ctx)
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

			if !c.expectImageOutput && c.expectOutput != "" {
				actualOutput, err := afero.ReadFile(fs, c.expectOutput)
				assert.NoError(t, err)
				assert.JSONEq(t, testOutput, string(actualOutput))
			}
		})
	}

}
