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
	"encoding/json"

	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
)

type Component struct {
	appstudioshared.ApplicationSnapshotComponent
	Violations []string `json:"violations"`
	Success    bool     `json:"success"`
}

type report struct {
	Success    bool        `json:"success"`
	Components []Component `json:"components"`
}

// Report the states of components from the snapshot
func Report(components []Component) (string, error, bool) {
	success := true

	// Set the report success, remains true if all components are successful
	for _, component := range components {
		if !component.Success {
			success = false
			break
		}
	}

	output := report{
		Success:    success,
		Components: components,
	}

	j, err := json.Marshal(output)
	if err != nil {
		return "", err, false
	}

	return string(j), nil, success
}
