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
	"errors"
	"fmt"

	"github.com/ghodss/yaml"
	app "github.com/redhat-appstudio/application-api/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

type Input struct {
	File  string
	JSON  string
	Image string
}

func DetermineInputSpec(fs afero.Fs, input Input) (*app.SnapshotSpec, error) {
	var snapshot app.SnapshotSpec

	// read Snapshot provided as a file
	if len(input.File) > 0 {
		content, err := afero.ReadFile(fs, input.File)
		if err != nil {
			log.Debugf("Problem reading application snapshot from file %s", input.File)
			return nil, err
		}

		err = yaml.Unmarshal(content, &snapshot)
		if err != nil {
			log.Debugf("Problem parsing application snapshot from file %s", input.File)
			return nil, fmt.Errorf("unable to parse Snapshot specification from %s: %w", input.File, err)
		}

		log.Debugf("Read application snapshot from file %s", input.File)
		return &snapshot, nil
	}

	// read Snapshot provided as a string
	if len(input.JSON) > 0 {
		// Unmarshall YAML into struct, exit on failure
		if err := yaml.Unmarshal([]byte(input.JSON), &snapshot); err != nil {
			log.Debugf("Problem parsing application snapshot from input param %s", input.JSON)
			return nil, fmt.Errorf("unable to parse Snapshot specification from input: %w", err)
		}

		log.Debug("Read application snapshot from input param")
		return &snapshot, nil
	}

	// create Snapshot with a single image
	if len(input.Image) > 0 {
		log.Debugf("Generating application snapshot from image reference %s", input.Image)
		return &app.SnapshotSpec{
			Components: []app.SnapshotComponent{
				{
					Name:           "Unnamed",
					ContainerImage: input.Image,
				},
			},
		}, nil
	}

	log.Debug("No application snapshot available")
	return nil, errors.New("neither Snapshot nor image reference provided to validate")
}
