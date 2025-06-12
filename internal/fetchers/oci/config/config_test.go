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

//go:build unit

package config

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	v1fake "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/utils"
	"github.com/conforma/cli/internal/utils/oci"
	"github.com/conforma/cli/internal/utils/oci/fake"
)

func TestFetchImageConfig(t *testing.T) {
	ref := name.MustParseReference("registry.local/test-image:latest")

	testcases := []struct {
		name     string
		setup    func(*fake.FakeClient)
		expected string
		err      string
	}{
		{
			name: "success",
			setup: func(client *fake.FakeClient) {
				image, err := mutate.Config(empty.Image, v1.Config{
					Labels: map[string]string{
						"io.k8s.display-name": "Test Image",
					},
				})
				require.NoError(t, err)
				client.On("Image", ref).Return(image, nil)
			},
			expected: `{"Labels":{"io.k8s.display-name":"Test Image"}}`,
		},
		{
			name: "error fetching image",
			setup: func(client *fake.FakeClient) {
				client.On("Image", ref).Return(empty.Image, errors.New("kaboom!"))
			},
			err: "kaboom!",
		},
		{
			name: "error fetching config file",
			setup: func(client *fake.FakeClient) {
				image := v1fake.FakeImage{}
				image.ConfigFileReturns(nil, errors.New("kaboom!"))
				client.On("Image", ref).Return(&image, nil)
			},
			err: "kaboom!",
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			client := fake.FakeClient{}
			if tt.setup != nil {
				tt.setup(&client)
			}
			ctx = oci.WithClient(ctx, &client)

			out, err := FetchImageConfig(ctx, ref)
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
	parentName, parentDigest, found := strings.Cut(parentURL, "@")
	require.True(t, found)

	testcases := []struct {
		name     string
		setup    func(*fake.FakeClient)
		expected string
		err      string
	}{
		{
			name: "success with name annotation",
			setup: func(client *fake.FakeClient) {
				image := mutate.Annotations(empty.Image, map[string]string{
					oci.BaseImageNameAnnotation: parentURL,
				})

				client.On("Image", ref).Return(image, nil)
			},
			expected: parentURL,
		},
		{
			name: "success with name and digest annotations",
			setup: func(client *fake.FakeClient) {
				image := mutate.Annotations(empty.Image, map[string]string{
					oci.BaseImageNameAnnotation:   parentName,
					oci.BaseImageDigestAnnotation: parentDigest,
				})

				client.On("Image", ref).Return(image, nil)
			},
			expected: parentURL,
		},
		{
			name: "error fetching image",
			setup: func(client *fake.FakeClient) {
				client.On("Image", ref).Return(empty.Image, errors.New("kaboom!"))
			},
			err: "kaboom!",
		},
		{
			name: "error fetching manifest",
			setup: func(client *fake.FakeClient) {
				image := v1fake.FakeImage{}
				image.ManifestReturns(nil, errors.New("kaboom!"))

				client.On("Image", ref).Return(&image, nil)
			},
			err: "kaboom!",
		},
		{
			name: "missing name annotation",
			setup: func(client *fake.FakeClient) {
				image := mutate.Annotations(empty.Image, map[string]string{
					oci.BaseImageDigestAnnotation: parentDigest,
				})

				client.On("Image", ref).Return(image, nil)
			},
			err: "unable to determine parent image",
		},
		{
			name: "missing digest annotation",
			setup: func(client *fake.FakeClient) {
				image := mutate.Annotations(empty.Image, map[string]string{
					oci.BaseImageNameAnnotation: parentName,
				})

				client.On("Image", ref).Return(image, nil)
			},
			err: "unable to determine parent image",
		},
		{
			name: "missing all annotations",
			setup: func(client *fake.FakeClient) {
				client.On("Image", ref).Return(empty.Image, nil)
			},
			err: "unable to determine parent image",
		},
		{
			name: "invalid name annoation",
			setup: func(client *fake.FakeClient) {
				image := mutate.Annotations(empty.Image, map[string]string{
					oci.BaseImageNameAnnotation:   "inv@lid",
					oci.BaseImageDigestAnnotation: parentDigest,
				})

				client.On("Image", ref).Return(image, nil)
			},
			err: "unable to parse parent image ref",
		},
		{
			name: "invalid digest annoation",
			setup: func(client *fake.FakeClient) {
				image := mutate.Annotations(empty.Image, map[string]string{
					oci.BaseImageNameAnnotation:   parentName,
					oci.BaseImageDigestAnnotation: "invalid",
				})

				client.On("Image", ref).Return(image, nil)
			},
			err: "unable to parse parent image ref",
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			client := fake.FakeClient{}
			if tt.setup != nil {
				tt.setup(&client)
			}
			ctx = oci.WithClient(ctx, &client)

			out, err := FetchParentImage(ctx, ref)
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
