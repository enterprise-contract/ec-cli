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

package image_config

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"

	"github.com/enterprise-contract/ec-cli/internal/utils"
)

func TestFetchImageConfig(t *testing.T) {
	ref := name.MustParseReference("registry.local/test-image:latest")

	opts := []remote.Option{
		remote.WithTransport(remote.DefaultTransport),
	}

	testcases := []struct {
		name     string
		setup    func(*mockClient)
		expected string
		err      string
	}{
		{
			name: "success",
			setup: func(client *mockClient) {
				image := &mockImage{}
				image.On("ConfigFile").Return(&v1.ConfigFile{
					Config: v1.Config{
						Labels: map[string]string{"io.k8s.display-name": "Test Image"},
					},
				}, nil)
				client.On("Image", ref, opts).Return(image, nil)
			},
			expected: `{"Labels":{"io.k8s.display-name":"Test Image"}}`,
		},
		{
			name: "error fetching image",
			setup: func(client *mockClient) {
				client.On("Image", ref, opts).Return(&mockImage{}, errors.New("kaboom!"))
			},
			err: "kaboom!",
		},
		{
			name: "error fetching config file",
			setup: func(client *mockClient) {
				image := &mockImage{}
				image.On("ConfigFile").Return(&v1.ConfigFile{}, errors.New("kaboom!"))
				client.On("Image", ref, opts).Return(image, nil)
			},
			err: "kaboom!",
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			client := mockClient{}
			if tt.setup != nil {
				tt.setup(&client)
			}
			ctx = WithClient(ctx, &client)

			out, err := FetchImageConfig(ctx, ref, opts...)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				require.Nil(t, out)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, string(out))

		})
	}
}

func TestFetchParentImage(t *testing.T) {
	ref := name.MustParseReference("registry.local/test-image:latest")
	parentURL := utils.WithDigest("registry.local/base-image")

	opts := []remote.Option{
		remote.WithTransport(remote.DefaultTransport),
	}

	testcases := []struct {
		name     string
		setup    func(*mockClient)
		expected string
		err      string
	}{
		{
			name: "success",
			setup: func(client *mockClient) {
				image := &mockImage{}
				image.On("Manifest").Return(&v1.Manifest{
					Annotations: map[string]string{BaseImageAnnotation: parentURL},
				}, nil)

				client.On("Image", ref, opts).Return(image, nil)
			},
			expected: parentURL,
		},
		{
			name: "error fetching image",
			setup: func(client *mockClient) {
				client.On("Image", ref, opts).Return(&mockImage{}, errors.New("kaboom!"))
			},
			err: "kaboom!",
		},
		{
			name: "error fetching manifest",
			setup: func(client *mockClient) {
				image := &mockImage{}
				image.On("Manifest").Return(&v1.Manifest{}, errors.New("kaboom!"))

				client.On("Image", ref, opts).Return(image, nil)
			},
			err: "kaboom!",
		},
		{
			name: "missing parent image annotation",
			setup: func(client *mockClient) {
				image := &mockImage{}
				image.On("Manifest").Return(&v1.Manifest{
					Annotations: map[string]string{},
				}, nil)

				client.On("Image", ref, opts).Return(image, nil)
			},
			err: "unable to determine parent image",
		},
		{
			name: "missing all annotations",
			setup: func(client *mockClient) {
				image := &mockImage{}
				image.On("Manifest").Return(&v1.Manifest{}, nil)

				client.On("Image", ref, opts).Return(image, nil)
			},
			err: "unable to determine parent image",
		},
		{
			name: "base image not pinned",
			setup: func(client *mockClient) {
				// Setup parent/base image mock
				parentURL := "registry.local/base-image:latest"
				parentRef, err := name.ParseReference(parentURL)
				if err != nil {
					panic(err)
				}
				parentImage := &mockImage{}
				parentImage.On("ConfigFile").Return(&v1.ConfigFile{
					Config: v1.Config{
						Labels: map[string]string{"io.k8s.display-name": "Base Image"},
					},
				}, nil)

				// Setup child image mock
				image := &mockImage{}
				image.On("Manifest").Return(&v1.Manifest{
					Annotations: map[string]string{BaseImageAnnotation: parentURL},
				}, nil)

				// Setup client
				client.On("Image", ref, opts).Return(image, nil)
				client.On("Image", parentRef, opts).Return(parentImage, nil)
			},
			err: "unable to parse parent image ref: a digest must contain exactly one '@' separator",
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			client := mockClient{}
			if tt.setup != nil {
				tt.setup(&client)
			}
			ctx = WithClient(ctx, &client)

			out, err := FetchParentImage(ctx, ref, opts...)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				require.Nil(t, out)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, out.String())

		})
	}
}
