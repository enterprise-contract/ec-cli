// Copyright The Conforma Contributors
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

package config

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/trace"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/conforma/cli/internal/utils/oci"
)

// FetchImageConfig retrieves the config for an image from its OCI registry.
func FetchImageConfig(ctx context.Context, ref name.Reference) (json.RawMessage, error) {
	if trace.IsEnabled() {
		region := trace.StartRegion(ctx, "ec:image-fetch-config")
		defer region.End()
		trace.Logf(ctx, "", "image=%q", ref)
	}

	image, err := oci.NewClient(ctx).Image(ref)
	if err != nil {
		return nil, err
	}
	configFile, err := image.ConfigFile()
	if err != nil {
		return nil, err
	}

	config, err := json.Marshal(configFile.Config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// FetchParentImage retrieves the reference to an image's parent image from its OCI registry.
func FetchParentImage(ctx context.Context, ref name.Reference) (name.Reference, error) {
	if trace.IsEnabled() {
		region := trace.StartRegion(ctx, "ec:image-fetch-parent-image")
		defer region.End()
		trace.Logf(ctx, "", "image=%q", ref)
	}

	image, err := oci.NewClient(ctx).Image(ref)
	if err != nil {
		return nil, err
	}

	manifest, err := image.Manifest()
	if err != nil {
		return nil, err
	}

	parentName := manifest.Annotations[oci.BaseImageNameAnnotation]
	if parentName == "" {
		return nil, fmt.Errorf(
			"unable to determine parent image, make sure %s annotation is set", oci.BaseImageNameAnnotation)
	}

	if !strings.Contains(parentName, "@") {
		parentDigest := manifest.Annotations[oci.BaseImageDigestAnnotation]
		if parentDigest == "" {
			return nil, fmt.Errorf(
				"unable to determine parent image, make sure %s annotation is set", oci.BaseImageDigestAnnotation)
		}
		parentName = fmt.Sprintf("%s@%s", parentName, parentDigest)
	}
	parentRef, err := name.NewDigest(parentName)
	if err != nil {
		return nil, fmt.Errorf("unable to parse parent image ref: %w", err)
	}
	return parentRef, nil
}
