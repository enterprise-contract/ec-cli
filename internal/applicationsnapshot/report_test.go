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

package applicationsnapshot

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/open-policy-agent/conftest/output"
	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	"github.com/stretchr/testify/assert"
)

//go:embed test_snapshot.json
var testSnapshot string

func Test_FullReport(t *testing.T) {
	var snapshot *appstudioshared.ApplicationSnapshotSpec
	err := json.Unmarshal([]byte(testSnapshot), &snapshot)
	if err != nil {
		fmt.Println(err)
	}

	expected := `
    {
      "success": true,
      "components": [
        {
          "name": "spam",
          "containerImage": "quay.io/caf/spam@sha256:123…",
          "violations": [],
          "warnings": null,
          "success": true
        },
        {
          "name": "bacon",
          "containerImage": "quay.io/caf/bacon@sha256:234…",
          "violations": [],
          "warnings": null,
          "success": true
        },
        {
          "name": "eggs",
          "containerImage": "quay.io/caf/eggs@sha256:345…",
          "violations": [],
          "warnings": null,
          "success": true
        }
      ]
    }
  `
	var components []Component
	for _, component := range snapshot.Components {
		c := Component{
			Violations: []output.Result{},
			Success:    true,
		}
		c.Name, c.ContainerImage = component.Name, component.ContainerImage
		components = append(components, c)
	}

	report, _, success := NewReport(components, false)
	assert.JSONEq(t, expected, report)
	assert.True(t, success)

	expected = `
    {
      "success": false,
      "components": [
        {
          "name": "spam",
          "containerImage": "quay.io/caf/spam@sha256:123…",
          "violations": [],
          "warnings": null,
          "success": true
        },
        {
          "name": "bacon",
          "containerImage": "quay.io/caf/bacon@sha256:234…",
          "violations": [],
          "warnings": null,
          "success": true
        },
        {
          "name": "eggs",
          "containerImage": "quay.io/caf/eggs@sha256:345…",
          "violations": [],
          "warnings": null,
          "success": true
        },
        {
          "name": "",
          "containerImage": "",
          "violations": null,
          "warnings": null,
          "success": false
        }
      ]
    }
  `
	components = append(components, Component{Success: false})
	report, _, success = NewReport(components, false)
	assert.JSONEq(t, expected, report)
	assert.False(t, success)
}

func Test_ShortReport(t *testing.T) {
	tests := []struct {
		name  string
		input Component
		want  shortReport
	}{
		{
			"testing one violation and warning",
			Component{
				Violations: []output.Result{
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
				},
				Warnings: []output.Result{
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
				},
				Success: false,
			},
			shortReport{
				Components: []shortComponent{
					{
						Violations: map[string][]string{
							"short_name": {"short report"},
						},
						Warnings: map[string][]string{
							"short_name": {"short report"},
						},
						TotalViolations: 1,
						TotalWarnings:   1,
						Success:         false,
						Name:            "",
					},
				},
				Success: false,
			},
		},
		{
			"testing no metadata",
			Component{
				Violations: []output.Result{
					{
						Message: "short report",
					},
				},
				Warnings: []output.Result{
					{
						Message: "short report",
					},
				},
				Success: false,
			},
			shortReport{
				Components: []shortComponent{
					{
						Violations:      map[string][]string{},
						Warnings:        map[string][]string{},
						TotalViolations: 1,
						TotalWarnings:   1,
						Success:         false,
						Name:            "",
					},
				},
				Success: false,
			},
		},
		{
			"testing multiple violations and warnings",
			Component{
				Violations: []output.Result{
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
				},
				Warnings: []output.Result{
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
				},
				Success: false,
			},
			shortReport{
				Components: []shortComponent{
					{
						Violations: map[string][]string{
							"short_name": {"short report", "There are 1 more \"short_name\" messages"},
						},
						Warnings: map[string][]string{
							"short_name": {"short report", "There are 1 more \"short_name\" messages"},
						},
						TotalViolations: 2,
						TotalWarnings:   2,
						Success:         false,
						Name:            "",
					},
				},
				Success: false,
			},
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("NewReport=%s", tc.name), func(t *testing.T) {
			msg, _, _ := NewReport([]Component{tc.input}, true)
			assertedMsg, _ := json.Marshal(tc.want)
			assert.Equal(t, string(assertedMsg), msg)
		})
	}

}
