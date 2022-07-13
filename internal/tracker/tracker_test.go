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

package tracker

import (
	"context"
	"os"
	"path"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
)

var sampleHashOne = v1.Hash{
	Algorithm: "sha256",
	Hex:       "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
}

var sampleHashTwo = v1.Hash{
	Algorithm: "sha256",
	Hex:       "a2c1615816029636903a8172775682e8bbb84c6fde8d74b6de1e198f19f95c72",
}

var expectedEffectiveOn = effectiveOn().Format(time.RFC3339)

func TestTrack(t *testing.T) {
	tests := []struct {
		name   string
		urls   []string
		output string
		input  string
	}{
		{
			name: "always insert at the front",
			urls: []string{
				"registry.com/repo:two@" + sampleHashTwo.String(),
				"registry.com/repo:one@" + sampleHashOne.String(),
			},
			output: `pipeline-bundles:
  registry.com/repo:
  - digest: ` + sampleHashOne.String() + `
    effective_on: "` + expectedEffectiveOn + `"
    tag: one
  - digest: ` + sampleHashTwo.String() + `
    effective_on: "` + expectedEffectiveOn + `"
    tag: two
`,
		},
		{
			name: "multiple repos",
			urls: []string{
				"registry.com/one:1.0@" + sampleHashOne.String(),
				"registry.com/two:2.0@" + sampleHashTwo.String(),
			},
			output: `pipeline-bundles:
  registry.com/one:
  - digest: ` + sampleHashOne.String() + `
    effective_on: "` + expectedEffectiveOn + `"
    tag: "1.0"
  registry.com/two:
  - digest: ` + sampleHashTwo.String() + `
    effective_on: "` + expectedEffectiveOn + `"
    tag: "2.0"
`,
		},
		{
			name: "update existing repo",
			urls: []string{
				"registry.com/repo:two@" + sampleHashTwo.String(),
			},
			input: `pipeline-bundles:
  registry.com/repo:
  - digest: ` + sampleHashOne.String() + `
    effective_on: "` + expectedEffectiveOn + `"
    tag: one
`,
			output: `pipeline-bundles:
  registry.com/repo:
  - digest: ` + sampleHashTwo.String() + `
    effective_on: "` + expectedEffectiveOn + `"
    tag: two
  - digest: ` + sampleHashOne.String() + `
    effective_on: "` + expectedEffectiveOn + `"
    tag: one
`,
		},
		{
			name: "update existing collection",
			urls: []string{
				"registry.com/two:2.0@" + sampleHashTwo.String(),
			},
			input: `pipeline-bundles:
  registry.com/one:
  - digest: ` + sampleHashOne.String() + `
    effective_on: "` + expectedEffectiveOn + `"
    tag: "1.0"
`,
			output: `pipeline-bundles:
  registry.com/one:
  - digest: ` + sampleHashOne.String() + `
    effective_on: "` + expectedEffectiveOn + `"
    tag: "1.0"
  registry.com/two:
  - digest: ` + sampleHashTwo.String() + `
    effective_on: "` + expectedEffectiveOn + `"
    tag: "2.0"
`,
		},
		{
			name: "create new collection",
			urls: []string{
				"registry.com/two:2.0@" + sampleHashTwo.String(),
			},
			input: `task-bundles:
  registry.com/one:
  - digest: ` + sampleHashOne.String() + `
    effective_on: "` + expectedEffectiveOn + `"
    tag: "1.0"
`,
			output: `pipeline-bundles:
  registry.com/two:
  - digest: ` + sampleHashTwo.String() + `
    effective_on: "` + expectedEffectiveOn + `"
    tag: "2.0"
task-bundles:
  registry.com/one:
  - digest: ` + sampleHashOne.String() + `
    effective_on: "` + expectedEffectiveOn + `"
    tag: "1.0"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputFile := ""
			if tt.input != "" {
				inputFile = path.Join(t.TempDir(), "input.yaml")
				f, err := os.Create(inputFile)
				assert.NoError(t, err)
				defer f.Close()
				_, err = f.WriteString(tt.input)
				assert.NoError(t, err)
			}
			output, err := Track(context.TODO(), tt.urls, "pipeline-bundles", inputFile)
			assert.NoError(t, err)
			assert.Equal(t, tt.output, string(output))
		})
	}

}
