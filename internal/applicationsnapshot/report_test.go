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

func Test_Report(t *testing.T) {
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

	report, _, success := Report(components)
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
	report, _, success = Report(components)
	assert.JSONEq(t, expected, report)
	assert.False(t, success)
}
