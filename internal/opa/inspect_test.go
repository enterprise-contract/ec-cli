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

package opa

import (
	"encoding/json"
	"testing"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/stretchr/testify/assert"
)

func Test_InspectMultiple(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		modules  []string
		expected string
		err      error
	}{
		{
			name:  "Smoke test",
			paths: []string{"foo/bar/bacon.rego"},
			modules: []string{hd.Doc(`
				package bacon

				# METADATA
				# title: Enough spam
				deny {
					input.spam_count > 42
				}
			`)},
			expected: hd.Doc(`
				[
					{
						"location":{
							"file":"foo/bar/bacon.rego",
							"row":5,
							"col":1
						},
						"path":[
							{"type":"var","value":"data"},
							{"type":"string","value":"bacon"},
							{"type":"string","value":"deny"}
						],
						"annotations":{
							"scope":"rule",
							"title":"Enough spam"
						}
					}
				]
			`),
			err: nil,
		},
	}
	for _, tt := range tests {
		results, err := inspectMultiple(tt.paths, tt.modules)
		assert.Equal(t, tt.err, err, tt.name)

		jsonResults, err := json.Marshal(results)
		if err != nil {
			panic(err)
		}
		assert.JSONEq(t, tt.expected, string(jsonResults), tt.expected, tt.name)
	}
}
