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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package definitionfile

import (
	"testing"

	cOutput "github.com/open-policy-agent/conftest/output"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/format"
	"github.com/hacbs-contract/ec-cli/internal/output"
)

func TestReport(t *testing.T) {
	cases := []struct {
		name    string
		output  []output.Output
		expect  string
		skipped bool
	}{
		{
			name: "success",
			output: []output.Output{
				{PolicyCheck: []cOutput.CheckResult{{FileName: "/path/to/pipeline.json"}}},
			},
			expect: `[{
				"filename": "/path/to/pipeline.json",
				"violations": [],
				"warnings": [],
				"success": true
			}]`,
		},
		{
			name: "warnings",
			output: []output.Output{
				{
					PolicyCheck: []cOutput.CheckResult{
						{
							FileName: "/path/to/pipeline.json",
							Warnings: []cOutput.Result{
								{Message: "running low in spam"},
								{Message: "not all like spam"},
							},
						},
					},
				},
			},
			expect: `[{
				"filename": "/path/to/pipeline.json",
				"violations": [],
				"warnings": [{"msg": "running low in spam"},{"msg": "not all like spam"}],
				"success": true
			}]`,
		},
		{
			name: "violations",
			output: []output.Output{
				{
					PolicyCheck: []cOutput.CheckResult{
						{
							FileName: "/path/to/pipeline.json",
							Failures: []cOutput.Result{
								{Message: "out of spam!"},
								{Message: "spam 💔"},
							},
						},
					},
				},
			},
			expect: `[{
				"filename": "/path/to/pipeline.json",
				"violations": [{"msg": "out of spam!"},{"msg": "spam 💔"}],
				"warnings": [],
				"success": false
			}]`,
		},
		{
			name:    "empty output",
			output:  []output.Output{},
			skipped: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Report{}
			for _, o := range c.output {
				r.Add(o)
			}
			fs := afero.NewMemMapFs()
			parser := format.NewTargetParser("ignored", nil, fs)

			for _, format := range []string{"json", "yaml"} {
				fname := "out." + format
				target := format + "=" + fname
				err := r.Write(target, parser)
				assert.NoError(t, err)

				if c.skipped {
					exists, err := afero.Exists(fs, fname)
					assert.NoError(t, err)
					assert.False(t, exists)

				} else {

					actualText, err := afero.ReadFile(fs, fname)
					assert.NoError(t, err)
					assert.YAMLEq(t, c.expect, string(actualText))
				}
			}
		})
	}
}
