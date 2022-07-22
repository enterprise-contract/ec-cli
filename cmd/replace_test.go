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

package cmd

import (
	"io/ioutil"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

// func replace(ctx context.Context, images []string, source string) ([]byte, error) {

const testDigest = "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"

func TestReplace(t *testing.T) {
	cases := []struct {
		name     string
		images   []string
		source   string
		expected string
		err      string
	}{
		{
			name: "replace matches",
			images: []string{
				// Does not occur in the source
				"registry.com/unmentioned/repo:0.9@" + testDigest,
				// Occurs once in the source
				"registry.com/some/repo:1.9@" + testDigest,
				// Occurs twice in the source
				"registry.com/other/repo:2.9@" + testDigest,
			},
			source: `
spec:
  pipelineRef:
	bundle: registry.com/some/repo:1.0
	name: simple-build
---
taskRef:
	bundle: registry.com/other/repo:2.0
---
bundle-o-landia: registry.com/other/repo@sha256:abc
`,
			expected: `
spec:
  pipelineRef:
	bundle: registry.com/some/repo:1.9@` + testDigest + `
	name: simple-build
---
taskRef:
	bundle: registry.com/other/repo:2.9@` + testDigest + `
---
bundle-o-landia: registry.com/other/repo:2.9@` + testDigest + `
`,
		},
		{
			name: "invalid image references",
			images: []string{
				// Missing repo, and tag or digest
				"registry.com",
				// Missing tag or digest
				"registry.com/repo",
			},
			err: "2 errors occurred",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sourceFile := path.Join(t.TempDir(), "source.yaml")
			err := ioutil.WriteFile(sourceFile, []byte(c.source), 0777)
			assert.NoError(t, err)
			got, err := replace(c.images, sourceFile)
			if c.err != "" {
				assert.ErrorContains(t, err, c.err)
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, c.expected, string(got))
		})
	}
}
