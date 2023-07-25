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

//go:build unit

// The contents of this file are meant to assist in writing unit tests. It requires the "unit" build
// tag which is not included when building the ec binary.
package fake

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
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
	parentImage := &FakeImage{}
	parentImage.On("ConfigFile").Return(&v1.ConfigFile{
		Config: v1.Config{
			Labels: map[string]string{"io.k8s.display-name": "Base Image"},
		},
	}, nil)

	// Setup child image mock
	image := &FakeImage{}
	image.On("Manifest").Return(&v1.Manifest{
		Annotations: map[string]string{oci.BaseImageNameAnnotation: parentURL},
	}, nil)
	image.On("ConfigFile").Return(&v1.ConfigFile{
		Config: v1.Config{
			Labels: map[string]string{"io.k8s.display-name": "Test Image"},
		},
	}, nil)

	// Options are functions that cannot be easily compared. We simply ignore
	// them here.
	opts := mock.MatchedBy(func([]remote.Option) bool {
		return true
	})

	// Setup client
	client := &FakeClient{}
	client.On("Image", ref, opts).Return(image, nil)
	client.On("Image", parentRef, opts).Return(parentImage, nil)

	return oci.WithClient(ctx, client)
}

type FakeClient struct {
	mock.Mock
}

func (m *FakeClient) Image(ref name.Reference, opts ...remote.Option) (v1.Image, error) {
	args := m.Called(ref, opts)
	return args.Get(0).(v1.Image), args.Error(1)
}

type FakeImage struct {
	mock.Mock
}

func (m *FakeImage) Layers() ([]v1.Layer, error) {
	args := m.Called()
	return args.Get(0).([]v1.Layer), args.Error(1)
}

func (m *FakeImage) MediaType() (types.MediaType, error) {
	args := m.Called()
	return args.Get(0).(types.MediaType), args.Error(1)
}

func (m *FakeImage) Size() (int64, error) {
	args := m.Called()
	return args.Get(0).(int64), args.Error(1)
}

func (m *FakeImage) ConfigName() (v1.Hash, error) {
	args := m.Called()
	return args.Get(0).(v1.Hash), args.Error(1)
}

func (m *FakeImage) ConfigFile() (*v1.ConfigFile, error) {
	args := m.Called()
	return args.Get(0).(*v1.ConfigFile), args.Error(1)
}

func (m *FakeImage) RawConfigFile() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (m *FakeImage) Digest() (v1.Hash, error) {
	args := m.Called()
	return args.Get(0).(v1.Hash), args.Error(1)
}

func (m *FakeImage) Manifest() (*v1.Manifest, error) {
	args := m.Called()
	return args.Get(0).(*v1.Manifest), args.Error(1)
}

func (m *FakeImage) RawManifest() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (m *FakeImage) LayerByDigest(v1.Hash) (v1.Layer, error) {
	args := m.Called()
	return args.Get(0).(v1.Layer), args.Error(1)
}

func (m *FakeImage) LayerByDiffID(v1.Hash) (v1.Layer, error) {
	args := m.Called()
	return args.Get(0).(v1.Layer), args.Error(1)
}
