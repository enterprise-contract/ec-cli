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
func Report(snapshot *appstudioshared.ApplicationSnapshotSpec) (string, error) {
	//TODO: set success based on violations
	output := report{Success: true}

	for _, image := range snapshot.Components {
		item := Component{
			Violations: []string{},
			Success:    true,
		}
		item.ContainerImage, item.Name = image.ContainerImage, image.Name
		output.Components = append(output.Components, item)
	}

	j, err := json.Marshal(output)
	if err != nil {
		return "", err
	}

	return string(j), nil
}
