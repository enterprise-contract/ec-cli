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
	"time"

	"github.com/open-policy-agent/conftest/output"
	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/format"
)

//go:embed test_snapshot.json
var testSnapshot string

func Test_ReportJson(t *testing.T) {
	var snapshot *appstudioshared.ApplicationSnapshotSpec
	err := json.Unmarshal([]byte(testSnapshot), &snapshot)
	assert.NoError(t, err)

	expected := `
    {
      "success": true,
	  "key": "my-public-key",
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

	report := NewReport(components, "my-public-key")
	reportJson, err := report.toFormat(JSON)
	assert.NoError(t, err)
	assert.JSONEq(t, expected, string(reportJson))
	assert.True(t, report.Success)

	expected = `
    {
      "success": false,
	  "key": "my-public-key",
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
	report = NewReport(components, "my-public-key")
	reportJson, err = report.toFormat(JSON)
	assert.NoError(t, err)
	assert.JSONEq(t, expected, string(reportJson))
	assert.False(t, report.Success)
}

func Test_ReportYaml(t *testing.T) {
	var snapshot *appstudioshared.ApplicationSnapshotSpec
	err := json.Unmarshal([]byte(testSnapshot), &snapshot)
	assert.NoError(t, err)

	expected := `
success: true
key: my-public-key
components:
  - name: spam
    containerImage: quay.io/caf/spam@sha256:123…
    violations: []
    warnings: null
    success: true
  - name: bacon
    containerImage: quay.io/caf/bacon@sha256:234…
    violations: []
    warnings: null
    success: true
  - name: eggs
    containerImage: quay.io/caf/eggs@sha256:345…
    violations: []
    warnings: null
    success: true
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

	report := NewReport(components, "my-public-key")
	reportYaml, err := report.toFormat(YAML)
	assert.NoError(t, err)
	assert.YAMLEq(t, expected, string(reportYaml))
	assert.True(t, report.Success)

	expected = `
success: false
key: my-public-key
components:
  - name: spam
    containerImage: quay.io/caf/spam@sha256:123…
    violations: []
    warnings: null
    success: true
  - name: bacon
    containerImage: quay.io/caf/bacon@sha256:234…
    violations: []
    warnings: null
    success: true
  - name: eggs
    containerImage: quay.io/caf/eggs@sha256:345…
    violations: []
    warnings: null
    success: true
  - name: ""
    containerImage: ""
    violations: null
    warnings: null
    success: false

`
	components = append(components, Component{Success: false})
	report = NewReport(components, "my-public-key")
	reportYaml, err = report.toFormat(YAML)
	assert.NoError(t, err)
	assert.YAMLEq(t, expected, string(reportYaml))
	assert.False(t, report.Success)
}

func Test_ReportSummary(t *testing.T) {
	tests := []struct {
		name  string
		input Component
		want  summary
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
			summary{
				Components: []componentSummary{
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
				Key:     "my-public-key",
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
			summary{
				Components: []componentSummary{
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
				Key:     "my-public-key",
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
			summary{
				Components: []componentSummary{
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
				Key:     "my-public-key",
			},
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("NewReport=%s", tc.name), func(t *testing.T) {
			report := NewReport([]Component{tc.input}, "my-public-key")
			assert.Equal(t, tc.want, report.toSummary())
		})
	}

}

func Test_ReportHACBS(t *testing.T) {
	cases := []struct {
		name       string
		expected   string
		components []Component
		success    bool
	}{
		{
			name: "success",
			expected: `
			{
				"failures": 0,
				"namespace": "release.main",
				"result": "SUCCESS",
				"successes": 3,
				"timestamp": "1970-01-01T00:00:00Z",
				"warnings": 0
			}`,
			components: []Component{{Success: true}, {Success: true}, {Success: true}},
			success:    true,
		},
		{
			name: "warning",
			expected: `
			{
				"failures": 0,
				"namespace": "release.main",
				"result": "WARNING",
				"successes": 2,
				"timestamp": "1970-01-01T00:00:00Z",
				"warnings": 1
			}`,
			components: []Component{
				{Success: true},
				{Success: true, Warnings: []output.Result{{Message: "this is a warning"}}},
			},
			success: true,
		},
		{
			name: "failure",
			expected: `
			{
				"failures": 1,
				"namespace": "release.main",
				"result": "FAILURE",
				"successes": 1,
				"timestamp": "1970-01-01T00:00:00Z",
				"warnings": 0
			}`,
			components: []Component{
				{Success: true},
				{Success: false, Violations: []output.Result{{Message: "this is a violation"}}},
			},
			success: false,
		},
		{
			name: "failure without violations",
			expected: `
			{
				"failures": 0,
				"namespace": "release.main",
				"result": "FAILURE",
				"successes": 1,
				"timestamp": "1970-01-01T00:00:00Z",
				"warnings": 0
			}`,
			components: []Component{{Success: false}, {Success: true}},
			success:    false,
		},
		{
			name: "failure over warning",
			expected: `
			{
				"failures": 1,
				"namespace": "release.main",
				"result": "FAILURE",
				"successes": 1,
				"timestamp": "1970-01-01T00:00:00Z",
				"warnings": 1
			}`,
			components: []Component{
				{Success: true},
				{Success: false, Violations: []output.Result{{Message: "this is a violation"}}},
				{Success: false, Warnings: []output.Result{{Message: "this is a warning"}}},
			},
			success: false,
		},
		{
			name: "skipped",
			expected: `
			{
				"failures": 0,
				"namespace": "release.main",
				"result": "SKIPPED",
				"successes": 0,
				"timestamp": "1970-01-01T00:00:00Z",
				"warnings": 0
			}`,
			components: []Component{},
			success:    true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			defaultWriter, err := fs.Create("default")
			assert.NoError(t, err)

			report := NewReport(c.components, "my-public-key")
			assert.False(t, report.created.IsZero())
			assert.Equal(t, c.success, report.Success)

			report.created = time.Unix(0, 0).UTC()

			p := format.NewTargetParser(JSON, defaultWriter, fs)
			assert.NoError(t, report.WriteAll([]string{"hacbs=report.json", "hacbs"}, p))

			reportText, err := afero.ReadFile(fs, "report.json")
			assert.NoError(t, err)
			assert.JSONEq(t, c.expected, string(reportText))

			defaultReportText, err := afero.ReadFile(fs, "default")
			assert.NoError(t, err)
			assert.JSONEq(t, c.expected, string(defaultReportText))
		})
	}
}
