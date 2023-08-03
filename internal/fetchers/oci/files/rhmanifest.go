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
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	redHatVendorLabelName  = "vendor"
	redHatVendorLabelValue = "Red Hat, Inc."
	redHatManifestPath     = "root/buildinfo/content_manifests"
)

type redHatManifest struct{}

func (redHatManifest) matcher(img v1.Image) (matcher, error) {
	if img == nil {
		return nil, nil
	}

	config, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}

	if vendor := config.Config.Labels[redHatVendorLabelName]; vendor == redHatVendorLabelValue {
		matcher := pathMatcher{redHatManifestPath}
		return matcher.match, nil
	}

	return nil, nil
}
