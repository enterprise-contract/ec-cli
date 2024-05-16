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

package files

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"

	"github.com/enterprise-contract/ec-cli/internal/utils/oci"
)

type extractor interface {
	matcher(v1.Image) (matcher, error)
}

type matcher func(*tar.Header) bool

var supported = []extractor{
	olmManifest{},
	redHatManifest{},
}

var supportedExtensions = []string{".yaml", ".yml", ".json"}

func ImageFiles(ctx context.Context, ref name.Reference) (map[string]json.RawMessage, error) {
	img, err := oci.NewClient(ctx).Image(ref)
	if err != nil {
		return nil, err
	}

	matchers := make([]matcher, 0, len(supported))
	for _, f := range supported {
		if m, err := f.matcher(img); err != nil {
			return nil, err
		} else if m != nil {
			matchers = append(matchers, m)
		}
	}

	if len(matchers) == 0 {
		return nil, nil
	}

	content := mutate.Extract(img)
	defer content.Close()
	archive := tar.NewReader(content)

	files := map[string]json.RawMessage{}
	for {
		header, err := archive.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		for _, matcher := range matchers {
			if !matcher(header) {
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
				break
			}

			files[header.Name] = data
			break
		}
	}

	return files, nil
}

type pathMatcher struct {
	path string
}

func (f *pathMatcher) match(header *tar.Header) bool {
	if header == nil {
		return false
	}

	name := header.Name

	// we're only interested in files in `<path>/*`
	if !strings.EqualFold(path.Dir(name), path.Clean(f.path)) {
		return false
	}

	ext := path.Ext(name)
	// we're only interested in files with specified extensions
	for _, e := range supportedExtensions {
		if strings.EqualFold(ext, e) {
			return true
		}
	}

	return false
}
