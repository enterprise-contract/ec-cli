// Copyright 2023 Red Hat, Inc.
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

package image_config

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Fetcher retrieves the config for an image from its OCI registry.
type Fetcher struct{}

func (*Fetcher) Fetch(ctx context.Context, ref name.Reference, opts ...remote.Option) (json.RawMessage, error) {
	image, err := NewClient(ctx).Image(ref, opts...)
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

const BaseImageAnnotation = "org.opencontainers.image.base.name"

// Fetcher retrieves the config for the base image of an image from its OCI registry.
type ParentFetcher struct{}

func (*ParentFetcher) Fetch(ctx context.Context, ref name.Reference, opts ...remote.Option) (json.RawMessage, error) {
	image, err := NewClient(ctx).Image(ref, opts...)
	if err != nil {
		return nil, err
	}

	manifest, err := image.Manifest()
	if err != nil {
		return nil, err
	}

	parentName := manifest.Annotations[BaseImageAnnotation]
	if parentName == "" {
		return nil, fmt.Errorf(
			"unable to determine parent image, make sure %s annotation is set", BaseImageAnnotation)
	}

	parentRef, err := name.NewDigest(parentName)
	if err != nil {
		return nil, fmt.Errorf("unable to parse parent image ref: %w", err)
	}

	f := Fetcher{}
	out, err := f.Fetch(ctx, parentRef, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch parent image: %w", err)
	}
	return out, nil
}
