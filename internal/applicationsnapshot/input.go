// Copyright The Enterprise Contract Contributors
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
	"context"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/go-multierror"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/exp/slices"
	"sigs.k8s.io/yaml"

	"github.com/enterprise-contract/ec-cli/internal/kubernetes"
	"github.com/enterprise-contract/ec-cli/internal/utils"
	"github.com/enterprise-contract/ec-cli/internal/utils/oci"
)

const unnamed = "Unnamed"

type Input struct {
	File     string // Deprecated: replaced by images
	JSON     string // Deprecated: replaced by images
	Image    string
	Snapshot string
	Images   string
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

func DetermineInputSpec(ctx context.Context, input Input) (*app.SnapshotSpec, error) {
	var snapshot snapshot
	provided := false

	if input.Images != "" {
		var content []byte
		var err error
		fs := utils.FS(ctx)
		content, err = afero.ReadFile(fs, input.Images)
		if err != nil {
			log.Debugf("could not read images from file: %v", err)
			// could not read as file so expecting string
			content = []byte(input.Images)
		}

		file, err := readSnapshotSource(content)
		if err != nil {
			return nil, err
		}
		snapshot.merge(file)
		provided = true
	}

	// read Snapshot provided as a file
	if input.File != "" {
		fs := utils.FS(ctx)
		content, err := afero.ReadFile(fs, input.File)
		if err != nil {
			return nil, err
		}
		file, err := readSnapshotSource(content)
		if err != nil {
			return nil, err
		}
		snapshot.merge(file)
		provided = true
	}

	// read Snapshot provided as a string
	if input.JSON != "" {
		json, err := readSnapshotSource([]byte(input.JSON))
		if err != nil {
			return nil, err
		}
		snapshot.merge(json)
		provided = true
	}

	// create Snapshot with a single image
	if input.Image != "" {
		log.Debugf("Generating application snapshot from image reference %s", input.Image)
		imageSnapshot := app.SnapshotSpec{
			Components: []app.SnapshotComponent{
				{
					Name:           unnamed,
					ContainerImage: input.Image,
				},
			},
		}
		snapshot.merge(imageSnapshot)
		provided = true
	}

	if input.Snapshot != "" {
		client, err := kubernetes.NewClient(ctx)
		if err != nil {
			log.Debugf("Unable to initialize Kubernetes Client: %v", err)
			return nil, err
		}

		cluster, err := client.FetchSnapshot(ctx, input.Snapshot)
		if err != nil {
			log.Debugf("Unable to fetch snapshot %s from Kubernetes cluster: %v", input.Snapshot, err)
			return nil, err
		}
		snapshot.merge(cluster.Spec)
		provided = true
	}

	if !provided {
		log.Debug("No application snapshot available")
		return nil, errors.New("neither Snapshot nor image reference provided to validate")
	}
	expandImageIndex(ctx, &snapshot.SnapshotSpec)

	return &snapshot.SnapshotSpec, nil
}

func readSnapshotSource(input []byte) (app.SnapshotSpec, error) {
	var file app.SnapshotSpec
	err := yaml.Unmarshal(input, &file)
	if err != nil {
		log.Debugf("Problem parsing application snapshot from file %s", input)
		return app.SnapshotSpec{}, fmt.Errorf("unable to parse Snapshot specification from %s: %w", input, err)
	}

	log.Debugf("Read application snapshot from file %s", input)
	return file, nil
}

func expandImageIndex(ctx context.Context, snap *app.SnapshotSpec) {
	client := oci.NewClient(ctx)
	// For an image index, remove the original component and replace it with an expanded component with all its image manifests
	var components []app.SnapshotComponent
	// Do not raise an error if the image is inaccessible, it will be handled as a violation when evaluated against the policy
	// This is to retain the original behavior of the `ec validate` command.
	var allErrors error = nil
	for _, component := range snap.Components {
		// Assume the image is not an image index or it isn't accessible
		components = append(components, component)
		ref, err := name.ParseReference(component.ContainerImage)
		if err != nil {
			allErrors = multierror.Append(allErrors, fmt.Errorf("unable to parse container image %s: %w", component.ContainerImage, err))
			continue
		}

		desc, err := client.Head(ref)
		if err != nil {
			allErrors = multierror.Append(allErrors, fmt.Errorf("unable to fetch descriptior for container image %s: %w", ref, err))
			continue
		}

		if !desc.MediaType.IsIndex() {
			continue
		}

		index, err := client.Index(ref)
		if err != nil {
			allErrors = multierror.Append(allErrors, fmt.Errorf("unable to fetch index for container image %s: %w", component.ContainerImage, err))
			continue
		}

		indexManifest, err := index.IndexManifest()
		if err != nil {
			allErrors = multierror.Append(allErrors, fmt.Errorf("unable to fetch index manifest for container image %s: %w", component.ContainerImage, err))
			continue
		}

		// The image is an image index and accessible so remove the image index itself and add index manifests
		components = components[:len(components)-1]
		for i, manifest := range indexManifest.Manifests {
			var arch string
			if manifest.Platform != nil && manifest.Platform.Architecture != "" {
				arch = manifest.Platform.Architecture
			} else {
				arch = fmt.Sprintf("noarch-%d", i)
			}
			archComponent := component
			archComponent.Name = fmt.Sprintf("%s-%s-%s", component.Name, manifest.Digest, arch)
			archComponent.ContainerImage = fmt.Sprintf("%s@%s", ref.Context().Name(), manifest.Digest)
			components = append(components, archComponent)
		}
	}

	snap.Components = components

	if allErrors != nil {
		log.Warnf("Encountered error while checking for Image Index: %v", allErrors)
	}
	log.Debugf("Snap component after expanding the image index is %v", snap.Components)
}
