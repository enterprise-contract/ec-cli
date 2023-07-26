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

package manifest

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"

	"github.com/enterprise-contract/ec-cli/internal/fetchers/oci"
)

func ImageManifests(ctx context.Context, ref name.Reference, opts ...remote.Option) (map[string]json.RawMessage, error) {
	img, err := oci.NewClient(ctx).Image(ref, opts...)
	if err != nil {
		return nil, err
	}

	content := mutate.Extract(img)
	defer content.Close()
	archive := tar.NewReader(content)

	manifests := map[string]json.RawMessage{}
	for {
		header, err := archive.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		name := header.Name

		// we're only interested in files in manifests/*
		if !strings.EqualFold(path.Dir(name), "manifests") {
			continue
		}

		// we're only interested in JSON or YAML files
		if ext := path.Ext(name); !strings.EqualFold(ext, ".yaml") && !strings.EqualFold(ext, ".json") {
			continue
		}

		// TODO: large files could be an issue. We do need to read the archive
		// in one pass making it difficult to not to buffer in memory.
		// Offloading to disk and read at the time of JSON marshalling the input
		// could be a solution, would need to be careful about memory usage at
		// that point.
		data, err := io.ReadAll(archive)
		if err != nil {
			return nil, err
		}

		// make sure we have JSON
		data, err = yaml.YAMLToJSON(data)
		if err != nil {
			log.Debugf("unable to read the layer content of `%s` as JSON or YAML, ignoring (%v)", header.Name, err)
			continue
		}

		manifests[header.Name] = data
	}

	return manifests, nil
}
