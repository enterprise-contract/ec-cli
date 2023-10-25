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

//go:build unit

// The contents of this file are meant to assist in writing unit tests. It requires the "unit" build
// tag which is not included when building the ec binary.
package fake

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/mock"

	"github.com/enterprise-contract/ec-cli/internal/fetchers/oci"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

func WithTestImageConfig(ctx context.Context, url string) context.Context {
	ref, err := name.NewDigest(url)
	if err != nil {
		panic(err)
	}

	// Setup parent/base image mock
	parentURL := utils.WithDigest("registry.local/base-image")
	parentRef, err := name.ParseReference(parentURL)
	if err != nil {
		panic(err)
	}
	parentImage, err := mutate.Config(empty.Image, v1.Config{
		Labels: map[string]string{
			"io.k8s.display-name": "Base Image",
		},
	})
	if err != nil {
		panic(err)
	}

	// Setup child image mock
	image := mutate.Annotations(empty.Image, map[string]string{
		oci.BaseImageNameAnnotation: parentURL,
	}).(v1.Image)
	image, err = mutate.Config(image, v1.Config{
		Labels: map[string]string{
			"io.k8s.display-name": "Test Image",
		},
	})
	if err != nil {
		panic(err)
	}

	// Setup client
	client := &FakeClient{}
	client.On("Image", ref, mock.Anything).Return(image, nil)
	client.On("Image", parentRef, mock.Anything).Return(parentImage, nil)

	return oci.WithClient(ctx, client)
}

type FakeClient struct {
	mock.Mock
}

func (m *FakeClient) Image(ref name.Reference, opts ...remote.Option) (v1.Image, error) {
	args := m.Called(ref, opts)
	var img v1.Image
	if maybeImg, ok := args.Get(0).(v1.Image); ok {
		img = maybeImg
	}
	return img, args.Error(1)
}

func (m *FakeClient) Layer(ref name.Digest, opts ...remote.Option) (v1.Layer, error) {
	args := m.Called(ref, opts)
	var layer v1.Layer
	if maybeLayer, ok := args.Get(0).(v1.Layer); ok {
		layer = maybeLayer
	}
	return layer, args.Error(1)
}
