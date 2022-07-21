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
	"bufio"
	"bytes"
	"context"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/arbitrary"
	"github.com/leanovate/gopter/gen"
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

func TestTrackerAddKeepsOrder(t *testing.T) {
	parameters := gopter.DefaultTestParameters()

	// uncomment when test fails and set the seed to the printed value
	// parameters.Rng.Seed(1234) -
	arbitraries := arbitrary.DefaultArbitraries()

	nonEmptyIdentifier := gen.Identifier().SuchThat(func(v string) bool {
		return len(v) > 0
	})
	arbitraries.RegisterGen(gen.SliceOf(
		gen.Struct(reflect.TypeOf(Record{}), map[string]gopter.Gen{
			"Digest":     gen.RegexMatch("^sha256:[a-f0-9]{64}$"),
			"Collection": nonEmptyIdentifier,
			"Tag":        gen.Identifier(),
			"Repository": nonEmptyIdentifier,
		})))

	properties := gopter.NewProperties(parameters)

	properties.Property("collections are sorted", arbitraries.ForAll(
		func(records []Record) bool {
			tracker := Tracker{}
			for _, r := range records {
				tracker.add(r)
			}

			raw, err := tracker.Output()
			if err != nil {
				panic(err)
			}

			buff := bytes.NewBuffer(raw)
			scanner := bufio.NewScanner(buff)
			scanner.Split(bufio.ScanLines)

			// at this level of identation, last string was
			lastAt := map[int]string{}
			lastLevel := 0
			for scanner.Scan() {
				line := scanner.Text()

				// ignore blank lines or document separator lines
				if line == "" || line == "---" {
					continue
				}

				// remove quotes, they're just messing with comparission below,
				// i.e. `"y"`` -> "y"
				line = strings.ReplaceAll(line, `"`, "")
				// remove trailing colon, it also messes with comparisson below,
				// i.e. "abc:" -> "abc"
				line = strings.TrimSuffix(line, ":")

				// counts the identation, i.e. number of spaces on the left
				level := len(line) - len(strings.TrimLeft(line, " "))

				// we're going to a lower level of identation, meaning we're now
				// processing a key that is not at the same, but at a lower
				// level, also meaning that the lines processed below this level
				// were were compared, i.e. we don't want to compare x and y
				// here:
				// a:
				//   x: 1
				//   z: 3
				// b:
				//   y: 2
				//   w: 4
				// only a and b, x and z and y and w
				if lastLevel > level {
					for i := level + 1; i <= lastLevel; i++ {
						delete(lastAt, i) // forget about unrelated lines
					}
				}

				if last, ok := lastAt[level]; ok && strings.Compare(last, line) > 0 {
					// we have found an unsorted line
					return false
				}

				// remember this line at its level for comparing to other lines
				// on this level
				lastAt[level] = line
				// remember the level so we can reset above
				lastLevel = level
			}

			// all lines are sorted
			return true
		},
	))

	properties.TestingRun(t)
}
