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
	"golang.org/x/exp/slices"
)

const unnamed = "Unnamed"

type Input struct {
	File  string
	JSON  string
	Image string
}

type snapshot struct {
	app.SnapshotSpec
}

func (s *snapshot) merge(snap app.SnapshotSpec) {
	if s.Application == "" {
		s.Application = snap.Application
	}

	if s.DisplayName == "" {
		s.DisplayName = snap.DisplayName
	}

	if s.DisplayDescription == "" {
		s.DisplayDescription = snap.DisplayDescription
	}

	images := map[string]string{}
	for _, c := range s.Components {
		images[c.ContainerImage] = c.Name
	}
	for _, c := range snap.Components {
		if name, ok := images[c.ContainerImage]; !ok || name == "" || name == unnamed {
			if ok {
				images[c.ContainerImage] = c.Name
				i := slices.IndexFunc(s.Components, func(x app.SnapshotComponent) bool {
					return x.ContainerImage == c.ContainerImage
				})
				s.Components[i].Name = c.Name
			} else {
				images[c.ContainerImage] = c.Name
				s.Components = append(s.Components, c)
			}
		}
	}
}

func DetermineInputSpec(fs afero.Fs, input Input) (*app.SnapshotSpec, error) {
	var snapshot snapshot

	// read Snapshot provided as a file
	if input.File != "" {
		content, err := afero.ReadFile(fs, input.File)
		if err != nil {
			log.Debugf("Problem reading application snapshot from file %s", input.File)
			return nil, err
		}

		var file app.SnapshotSpec
		err = yaml.Unmarshal(content, &file)
		if err != nil {
			log.Debugf("Problem parsing application snapshot from file %s", input.File)
			return nil, fmt.Errorf("unable to parse Snapshot specification from %s: %w", input.File, err)
		}

		log.Debugf("Read application snapshot from file %s", input.File)
		snapshot.merge(file)
	}

	// read Snapshot provided as a string
	if input.JSON != "" {
		var json app.SnapshotSpec
		// Unmarshall YAML into struct, exit on failure
		if err := yaml.Unmarshal([]byte(input.JSON), &json); err != nil {
			log.Debugf("Problem parsing application snapshot from input param %s", input.JSON)
			return nil, fmt.Errorf("unable to parse Snapshot specification from input: %w", err)
		}

		log.Debug("Read application snapshot from input param")
		snapshot.merge(json)
	}

	// create Snapshot with a single image
	if input.Image != "" {
		log.Debugf("Generating application snapshot from image reference %s", input.Image)
		snapshot.merge(app.SnapshotSpec{
			Components: []app.SnapshotComponent{
				{
					Name:           unnamed,
					ContainerImage: input.Image,
				},
			},
		})
	}

	if len(snapshot.Components) == 0 {
		log.Debug("No application snapshot available")
		return nil, errors.New("neither Snapshot nor image reference provided to validate")
	}

	return &snapshot.SnapshotSpec, nil
}
