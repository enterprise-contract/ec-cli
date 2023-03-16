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

func DetermineInputSpec(fs afero.Fs, filePath string, input string, imageRef string) (*app.SnapshotSpec, error) {
	var appSnapshot app.SnapshotSpec

	// read ApplicationSnapshot provided as a file
	if len(filePath) > 0 {
		content, err := afero.ReadFile(fs, filePath)
		if err != nil {
			log.Debugf("Problem reading application snapshot from file %s", filePath)
			return nil, err
		}

		err = yaml.Unmarshal(content, &appSnapshot)
		if err != nil {
			log.Debugf("Problem parsing application snapshot from file %s", filePath)
			return nil, fmt.Errorf("unable to parse ApplicationSnapshot file at %s: %w", filePath, err)
		}

		log.Debugf("Read application snapshot from file %s", filePath)
		return &appSnapshot, nil
	}

	// read ApplicationSnapshot provided as a string
	if len(input) > 0 {
		// Unmarshall YAML into struct, exit on failure
		if err := yaml.Unmarshal([]byte(input), &appSnapshot); err != nil {
			log.Debugf("Problem parsing application snapshot from input param %s", input)
			return nil, fmt.Errorf("unable to parse ApplicationSnapshot from input: %w", err)
		}

		log.Debug("Read application snapshot from input param")
		return &appSnapshot, nil
	}

	// create ApplicationSnapshot with a single image
	if len(imageRef) > 0 {
		log.Debugf("Generating application snapshot from imageRef %s", imageRef)
		return &app.SnapshotSpec{
			Components: []app.SnapshotComponent{
				{
					Name:           "Unnamed",
					ContainerImage: imageRef,
				},
			},
		}, nil
	}

	log.Debug("No application snapshot available")
	return nil, errors.New("neither ApplicationSnapshot nor image reference provided to validate")
}
