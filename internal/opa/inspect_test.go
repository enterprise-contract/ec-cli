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

package opa

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestInspectDir(t *testing.T) {
	files := map[string]string{
		"spam.rego": hd.Doc(`
			package spam

			# METADATA
			# title: Enough spam
			deny {
				input.spam_count > 42
			}
		`),
		"spam_test.rego":   "ignored",
		"spammy_TEST.rego": "ignored",
		"spam.text":        "ignored",
		"more/bacon.REGO": hd.Doc(`
			package more.bacon

			# METADATA
			# title: Enough bacon
			deny {
				input.bacon_count > 42
			}
		`),
	}

	cases := []struct {
		name    string
		symlink bool
	}{
		{name: "simple"},
		{name: "symlink", symlink: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Must use OsFs so we can test symlinks are working as expected
			fs := afero.NewOsFs()
			root := t.TempDir()

			policiesDir := filepath.Join(root, "policies")

			// Setup test data
			for path, value := range files {
				fullpath := filepath.Join(policiesDir, path)
				dir := filepath.Dir(fullpath)
				require.NoError(t, fs.MkdirAll(dir, 0755))
				require.NoError(t, afero.WriteFile(fs, fullpath, []byte(value), 0660))
			}

			if c.symlink {
				symlink := filepath.Join(root, "symlink")
				require.NoError(t, os.Symlink(policiesDir, symlink))
				policiesDir = symlink
			}

			annotations, err := InspectDir(fs, policiesDir)
			require.NoError(t, err)

			jsonAnnotations, err := json.MarshalIndent(annotations, "", "  ")
			require.NoError(t, err)
			snaps.MatchSnapshot(t, string(jsonAnnotations))
		})
	}
}
