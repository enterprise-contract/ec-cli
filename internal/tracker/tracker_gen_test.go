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

//go:build generative

package tracker

import (
	"bufio"
	"bytes"
	"reflect"
	"strings"
	"testing"
	"unicode"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/arbitrary"
	"github.com/leanovate/gopter/gen"
)

func TestTrackerAddKeepsOrder(t *testing.T) {
	parameters := gopter.DefaultTestParameters()

	// uncomment when test fails and set the seed to the printed value
	// parameters.Rng.Seed(1234)
	arbitraries := arbitrary.DefaultArbitraries()

	nonEmptyIdentifier := gen.Identifier().SuchThat(func(v string) bool {
		return len(v) > 0
	})
	arbitraries.RegisterGen(gen.SliceOf(
		gen.Struct(reflect.TypeOf(taskRecord{}), map[string]gopter.Gen{
			"Ref":         gen.RegexMatch("^([[:alnum:]]+:)?[[:xdigit:]]+$"),
			"EffectiveOn": gen.Time(),
			"ExpiresOn":   gen.PtrOf(gen.Time()),
			"Tag":         gen.Identifier(),
			"Repository":  nonEmptyIdentifier,
		})))

	properties := gopter.NewProperties(parameters)

	properties.Property("collections are sorted", arbitraries.ForAll(
		func(records []taskRecord) bool {
			tracker, err := newTracker(nil)
			if err != nil {
				t.Fatal(err)
			}

			for _, r := range records {
				tracker.addTrustedTaskRecord(ociPrefix, r)
			}

			raw, err := tracker.Output()
			if err != nil {
				panic(err)
			}

			buff := bytes.NewBuffer(raw)
			scanner := bufio.NewScanner(buff)
			scanner.Split(bufio.ScanLines)

			// at this level of indentation, last string was
			lastAt := map[int]string{}
			lastLevel := 0
			for scanner.Scan() {
				line := scanner.Text()

				// ignore blank lines or document separator lines
				if line == "" || line == "---" {
					continue
				}

				if strings.HasPrefix(strings.TrimLeftFunc(line, unicode.IsSpace), "?") {
					// complex key, next line is the value
					_, line, _ = strings.Cut(line, "?")
					scanner.Scan()
				}

				// remove quotes, they're just messing with comparisons below,
				// i.e. `"y"`` -> "y"
				line = strings.ReplaceAll(line, `"`, "")
				// focus only on keys, so disregard everything after and
				// including ":"
				line, _, _ = strings.Cut(line, ":")

				// counts the indentation, i.e. number of spaces on the left
				level := len(line) - len(strings.TrimLeft(line, " "))

				// we're going to a lower level of indentation, meaning we're now
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
