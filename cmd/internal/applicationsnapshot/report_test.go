/*
Copyright © 2022 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package applicationsnapshot

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"

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
          "success": true
        },
        {
          "name": "bacon",
          "containerImage": "quay.io/caf/bacon@sha256:234…",
          "violations": [],
          "success": true
        },
        {
          "name": "eggs",
          "containerImage": "quay.io/caf/eggs@sha256:345…",
          "violations": [],
          "success": true
        }
      ]
    }
  `

	report, _ := Report(snapshot)
	assert.JSONEq(t, expected, report)
}
