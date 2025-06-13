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

package oci

import (
	"context"
	"errors"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1fake "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/utils/oci"
	"github.com/conforma/cli/internal/utils/oci/fake"
)

func TestOCIBlob(t *testing.T) {
	cases := []struct {
		name      string
		data      string
		uri       *ast.Term
		err       bool
		remoteErr error
	}{
		{
			name: "success",
			data: `{"spam": "maps"}`,
			uri:  ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
		},
		{
			name: "unexpected uri type",
			data: `{"spam": "maps"}`,
			uri:  ast.IntNumberTerm(42),
			err:  true,
		},
		{
			name: "missing digest",
			data: `{"spam": "maps"}`,
			uri:  ast.StringTerm("registry.local/spam:latest"),
			err:  true,
		},
		{
			name: "invalid digest size",
			data: `{"spam": "maps"}`,
			uri:  ast.StringTerm("registry.local/spam@sha256:4e388ab"),
			err:  true,
		},
		{
			name:      "remote error",
			data:      `{"spam": "maps"}`,
			uri:       ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
			remoteErr: errors.New("boom!"),
			err:       true,
		},
		{
			name: "unexpected digest",
			data: `{"spam": "mapssssss"}`,
			uri:  ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
			err:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := fake.FakeClient{}
			if c.remoteErr != nil {
				client.On("Layer", mock.Anything, mock.Anything).Return(nil, c.remoteErr)
			} else {
				layer := static.NewLayer([]byte(c.data), types.OCIUncompressedLayer)
				client.On("Layer", mock.Anything, mock.Anything).Return(layer, nil)
			}
			ctx := oci.WithClient(context.Background(), &client)
			bctx := rego.BuiltinContext{Context: ctx}

			blob, err := ociBlob(bctx, c.uri)
			require.NoError(t, err)
			if c.err {
				require.Nil(t, blob)
			} else {
				require.NotNil(t, blob)
				data, ok := blob.Value.(ast.String)
				require.True(t, ok)
				require.Equal(t, c.data, string(data))
			}
		})
	}
}

func TestOCIDescriptorManifest(t *testing.T) {
	cases := []struct {
		name           string
		ref            *ast.Term
		descriptor     *v1.Descriptor
		resolvedDigest string
		resolveErr     error
		headErr        error
		wantErr        bool
	}{
		{
			name: "complete image manifest",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			descriptor: &v1.Descriptor{
				MediaType: types.OCIManifestSchema1,
				Size:      123,
				Digest: v1.Hash{
					Algorithm: "sha256",
					Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
				},
				Data: []byte(`{"data": "config"}`),
				URLs: []string{"https://config-1.local/spam", "https://config-2.local/spam"},
				Annotations: map[string]string{
					"config.annotation.1": "config.annotation.value.1",
					"config.annotation.2": "config.annotation.value.2",
				},
				Platform: &v1.Platform{
					Architecture: "arch",
					OS:           "os",
					OSVersion:    "os-version",
					OSFeatures:   []string{"os-feature-1", "os-feature-2"},
					Variant:      "variant",
					Features:     []string{"feature-1", "feature-2"},
				},
				ArtifactType: "artifact-type",
			},
		},
		{
			name: "minimal image manifest",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			descriptor: &v1.Descriptor{
				MediaType: types.OCIManifestSchema1,
				Size:      123,
				Digest: v1.Hash{
					Algorithm: "sha256",
					Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
				},
			},
		},
		{
			name: "minimal image index",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			descriptor: &v1.Descriptor{
				MediaType: types.OCIImageIndex,
				Size:      123,
				Digest: v1.Hash{
					Algorithm: "sha256",
					Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
				},
			},
		},
		{
			name:           "missing digest",
			ref:            ast.StringTerm("registry.local/spam:latest"),
			resolvedDigest: "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
			descriptor: &v1.Descriptor{
				MediaType: types.OCIManifestSchema1,
				Size:      123,
				Digest: v1.Hash{
					Algorithm: "sha256",
					Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
				},
			},
		},
		{
			name:       "resolve error",
			ref:        ast.StringTerm("registry.local/spam:latest"),
			resolveErr: errors.New("kaboom!"),
			wantErr:    true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := fake.FakeClient{}
			if c.headErr != nil {
				client.On("Head", mock.Anything).Return(nil, c.headErr)
			} else {
				client.On("Head", mock.Anything).Return(c.descriptor, nil)
			}
			if c.resolveErr != nil {
				client.On("ResolveDigest", mock.Anything).Return("", c.resolveErr)
			} else if c.resolvedDigest != "" {
				client.On("ResolveDigest", mock.Anything).Return(c.resolvedDigest, nil)
			}
			ctx := oci.WithClient(context.Background(), &client)
			bctx := rego.BuiltinContext{Context: ctx}

			got, err := ociDescriptor(bctx, c.ref)
			require.NoError(t, err)
			if c.wantErr {
				require.Nil(t, got)
			} else {
				require.NotNil(t, got)
				snaps.MatchJSON(t, got)
			}
		})
	}
}

func TestOCIDescriptorErrors(t *testing.T) {
	cases := []struct {
		name string
		ref  *ast.Term
	}{
		{
			name: "bad image ref",
			ref:  ast.StringTerm("......registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
		},
		{
			name: "bad image ref without digest",
			ref:  ast.StringTerm("."),
		},
		{
			name: "invalid ref type",
			ref:  ast.IntNumberTerm(42),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := fake.FakeClient{}
			client.On("Head", mock.Anything, mock.Anything).Return(nil, errors.New("expected"))
			ctx := oci.WithClient(context.Background(), &client)
			bctx := rego.BuiltinContext{Context: ctx}

			got, err := ociDescriptor(bctx, c.ref)
			require.NoError(t, err)
			require.Nil(t, got)
		})
	}
}

func TestOCIImageManifest(t *testing.T) {
	cases := []struct {
		name           string
		ref            *ast.Term
		manifest       *v1.Manifest
		resolvedDigest string
		resolveErr     error
		imageErr       error
		manifestErr    error
		wantErr        bool
	}{
		{
			name: "complete image manifest",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			manifest: &v1.Manifest{
				SchemaVersion: 2,
				MediaType:     types.OCIManifestSchema1,
				Config: v1.Descriptor{
					MediaType: types.OCIConfigJSON,
					Size:      123,
					Digest: v1.Hash{
						Algorithm: "sha256",
						Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
					},
					Data: []byte(`{"data": "config"}`),
					URLs: []string{"https://config-1.local/spam", "https://config-2.local/spam"},
					Annotations: map[string]string{
						"config.annotation.1": "config.annotation.value.1",
						"config.annotation.2": "config.annotation.value.2",
					},
					Platform: &v1.Platform{
						Architecture: "arch",
						OS:           "os",
						OSVersion:    "os-version",
						OSFeatures:   []string{"os-feature-1", "os-feature-2"},
						Variant:      "variant",
						Features:     []string{"feature-1", "feature-2"},
					},
					ArtifactType: "artifact-type",
				},
				Layers: []v1.Descriptor{
					{
						MediaType: types.OCILayer,
						Size:      9999,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "325392e8dd2826a53a9a35b7a7f8d71683cd27ebc2c73fee85dab673bc909b67",
						},
						Data: []byte(`{"data": "layer"}`),
						URLs: []string{"https://layer-1.local/spam", "https://layer-2.local/spam"},
						Annotations: map[string]string{
							"layer.annotation.1": "layer.annotation.value.1",
							"layer.annotation.2": "layer.annotation.value.2",
						},
						Platform: &v1.Platform{
							Architecture: "arch",
							OS:           "os",
							OSVersion:    "os-version",
							OSFeatures:   []string{"os-feature-1", "os-feature-2"},
							Variant:      "variant",
							Features:     []string{"feature-1", "feature-2"},
						},
						ArtifactType: "artifact-type",
					},
				},
				Annotations: map[string]string{
					"manifest.annotation.1": "config.annotation.value.1",
					"manifest.annotation.2": "config.annotation.value.2",
				},
				Subject: &v1.Descriptor{
					MediaType: types.OCIManifestSchema1,
					Size:      8888,
					Digest: v1.Hash{
						Algorithm: "sha256",
						Hex:       "d9298a10d1b0735837dc4bd85dac641b0f3cef27a47e5d53a54f2f3f5b2fcffa",
					},
					Data: []byte(`{"data": "subject"}`),
					URLs: []string{"https://subject-1.local/spam", "https://subject-2.local/spam"},
					Annotations: map[string]string{
						"subject.annotation.1": "subject.annotation.value.1",
						"subject.annotation.2": "subject.annotation.value.2",
					},
					Platform: &v1.Platform{
						Architecture: "arch",
						OS:           "os",
						OSVersion:    "os-version",
						OSFeatures:   []string{"os-feature-1", "os-feature-2"},
						Variant:      "variant",
						Features:     []string{"feature-1", "feature-2"},
					},
					ArtifactType: "artifact-type",
				},
			},
		},
		{
			name: "minimal image manifest",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			manifest: &v1.Manifest{
				SchemaVersion: 2,
				MediaType:     types.OCIManifestSchema1,
				Config: v1.Descriptor{
					MediaType: types.OCIConfigJSON,
					Size:      123,
					Digest: v1.Hash{
						Algorithm: "sha256",
						Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
					},
				},
				Layers: []v1.Descriptor{
					{
						MediaType: types.OCILayer,
						Size:      9999,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "325392e8dd2826a53a9a35b7a7f8d71683cd27ebc2c73fee85dab673bc909b67",
						},
					},
				},
			},
		},
		{
			name:           "missing digest",
			ref:            ast.StringTerm("registry.local/spam:latest"),
			resolvedDigest: "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
			manifest: &v1.Manifest{
				SchemaVersion: 2,
				MediaType:     types.OCIManifestSchema1,
				Config: v1.Descriptor{
					MediaType: types.OCIConfigJSON,
					Size:      123,
					Digest: v1.Hash{
						Algorithm: "sha256",
						Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
					},
				},
				Layers: []v1.Descriptor{
					{
						MediaType: types.OCILayer,
						Size:      9999,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "325392e8dd2826a53a9a35b7a7f8d71683cd27ebc2c73fee85dab673bc909b67",
						},
					},
				},
			},
		},
		{
			name:    "bad image ref",
			ref:     ast.StringTerm("......registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			wantErr: true,
		},
		{
			name:    "bad image ref without digest",
			ref:     ast.StringTerm("."),
			wantErr: true,
		},
		{
			name:    "invalid ref type",
			ref:     ast.IntNumberTerm(42),
			wantErr: true,
		},
		{
			name:        "image error",
			ref:         ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			manifestErr: errors.New("kaboom!"),
			wantErr:     true,
		},
		{
			name:       "resolve error",
			ref:        ast.StringTerm("registry.local/spam:latest"),
			resolveErr: errors.New("kaboom!"),
			wantErr:    true,
		},
		{
			name:     "nil manifest",
			ref:      ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			manifest: nil,
			wantErr:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := fake.FakeClient{}
			if c.imageErr != nil {
				client.On("Image", mock.Anything, mock.Anything).Return(nil, c.imageErr)
			} else {
				imageManifest := v1fake.FakeImage{}
				imageManifest.ManifestReturns(c.manifest, c.manifestErr)
				client.On("Image", mock.Anything, mock.Anything).Return(&imageManifest, nil)
			}
			if c.resolveErr != nil {
				client.On("ResolveDigest", mock.Anything).Return("", c.resolveErr)
			} else if c.resolvedDigest != "" {
				client.On("ResolveDigest", mock.Anything).Return(c.resolvedDigest, nil)
			}
			ctx := oci.WithClient(context.Background(), &client)
			bctx := rego.BuiltinContext{Context: ctx}

			got, err := ociImageManifest(bctx, c.ref)
			require.NoError(t, err)
			if c.wantErr {
				require.Nil(t, got)
			} else {
				require.NotNil(t, got)
				snaps.MatchJSON(t, got)
			}
		})
	}
}
func TestOCIImageFiles(t *testing.T) {

	image, err := crane.Image(map[string][]byte{
		"autoexec.bat":              []byte(`@ECHO OFF`),
		"manifests/a.json":          []byte(`{"a":1}`),
		"manifests/b.yaml":          []byte(`b: 2`),
		"manifests/c.xml":           []byte(`<?xml version="1.0" encoding="UTF-8"?>`),
		"manifests/unreadable.yaml": []byte(`***`),
		"manifests/unreadable.json": []byte(`***`),
	})
	require.NoError(t, err)

	cases := []struct {
		name      string
		paths     *ast.Term
		expected  string
		uri       *ast.Term
		err       bool
		remoteErr error
	}{
		{
			name:     "success",
			paths:    ast.ArrayTerm(ast.StringTerm("manifests")),
			expected: `{"manifests/a.json": {"a": 1}, "manifests/b.yaml": {"b": 2}}`,
			uri:      ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
		},
		{
			name: "non string URI",
			uri:  ast.BooleanTerm(true),
		},
		{
			name: "unpinned",
			uri:  ast.StringTerm("registry.local/spam:latest"),
		},
		{
			name:  "paths not an Array",
			paths: ast.BooleanTerm(true),
			uri:   ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
		},
		{
			name:  "path not a String",
			paths: ast.ArrayTerm(ast.BooleanTerm(true)),
			uri:   ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
		},
		{
			name:      "remote error",
			paths:     ast.ArrayTerm(ast.StringTerm("manifests")),
			uri:       ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
			remoteErr: errors.New("kaboom!"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := fake.FakeClient{}
			if c.remoteErr != nil {
				client.On("Image", mock.Anything).Return(nil, c.remoteErr)
			} else {
				client.On("Image", mock.Anything).Return(image, nil)
			}

			ctx := oci.WithClient(context.Background(), &client)
			bctx := rego.BuiltinContext{Context: ctx}

			files, err := ociImageFiles(bctx, c.uri, c.paths)
			require.NoError(t, err)
			if c.err || c.expected == "" {
				require.Nil(t, files)
			} else {
				require.NotNil(t, files)
				require.JSONEq(t, c.expected, files.String())
			}
		})
	}
}

func TestOCIImageIndex(t *testing.T) {
	cases := []struct {
		name             string
		ref              *ast.Term
		indexManifest    *v1.IndexManifest
		resolvedDigest   string
		resolveErr       error
		indexErr         error
		indexManifestErr error
		wantErr          bool
	}{
		{
			name: "complete image manifest",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			indexManifest: &v1.IndexManifest{
				SchemaVersion: 2,
				MediaType:     types.OCIManifestSchema1,
				Manifests: []v1.Descriptor{
					{
						MediaType: types.OCIConfigJSON,
						Size:      123,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
						},
						Data: []byte(`{"data": "config"}`),
						URLs: []string{"https://config-1.local/spam", "https://config-2.local/spam"},
						Annotations: map[string]string{
							"config.annotation.1": "config.annotation.value.1",
							"config.annotation.2": "config.annotation.value.2",
						},
						Platform: &v1.Platform{
							Architecture: "arch",
							OS:           "os",
							OSVersion:    "os-version",
							OSFeatures:   []string{"os-feature-1", "os-feature-2"},
							Variant:      "variant",
							Features:     []string{"feature-1", "feature-2"},
						},
						ArtifactType: "artifact-type",
					},
				},
				Annotations: map[string]string{
					"manifest.annotation.1": "config.annotation.value.1",
					"manifest.annotation.2": "config.annotation.value.2",
				},
				Subject: &v1.Descriptor{
					MediaType: types.OCIManifestSchema1,
					Size:      8888,
					Digest: v1.Hash{
						Algorithm: "sha256",
						Hex:       "d9298a10d1b0735837dc4bd85dac641b0f3cef27a47e5d53a54f2f3f5b2fcffa",
					},
					Data: []byte(`{"data": "subject"}`),
					URLs: []string{"https://subject-1.local/spam", "https://subject-2.local/spam"},
					Annotations: map[string]string{
						"subject.annotation.1": "subject.annotation.value.1",
						"subject.annotation.2": "subject.annotation.value.2",
					},
					Platform: &v1.Platform{
						Architecture: "arch",
						OS:           "os",
						OSVersion:    "os-version",
						OSFeatures:   []string{"os-feature-1", "os-feature-2"},
						Variant:      "variant",
						Features:     []string{"feature-1", "feature-2"},
					},
					ArtifactType: "artifact-type",
				},
			},
		},
		{
			name: "minimal image manifest",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			indexManifest: &v1.IndexManifest{
				SchemaVersion: 2,
				MediaType:     types.OCIManifestSchema1,
				Manifests: []v1.Descriptor{
					{
						MediaType: types.OCIConfigJSON,
						Size:      123,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
						},
					},
				},
			},
		},
		{
			name:           "missing digest",
			ref:            ast.StringTerm("registry.local/spam:latest"),
			resolvedDigest: "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
			indexManifest: &v1.IndexManifest{
				SchemaVersion: 2,
				MediaType:     types.OCIManifestSchema1,
				Manifests: []v1.Descriptor{
					{
						MediaType: types.OCIConfigJSON,
						Size:      123,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
						},
					},
				},
			},
		},
		{
			name:    "bad image ref",
			ref:     ast.StringTerm("......registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			wantErr: true,
		},
		{
			name:    "bad image ref without digest",
			ref:     ast.StringTerm("."),
			wantErr: true,
		},
		{
			name:    "invalid ref type",
			ref:     ast.IntNumberTerm(42),
			wantErr: true,
		},
		{
			name:             "image error",
			ref:              ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			indexManifestErr: errors.New("kaboom!"),
			wantErr:          true,
		},
		{
			name:       "resolve error",
			ref:        ast.StringTerm("registry.local/spam:latest"),
			resolveErr: errors.New("kaboom!"),
			wantErr:    true,
		},
		{
			name:          "nil manifest",
			ref:           ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			indexManifest: nil,
			wantErr:       true,
		},
		{
			name:          "nil manifest",
			ref:           ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			indexManifest: nil,
			indexErr:      errors.New("they say nothing is impossible, but i do nothing everyday"),
			wantErr:       true,
		},
		{
			name:    "invalid ref type",
			ref:     ast.StringTerm("registry.local/spam:latest@sha256@:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := fake.FakeClient{}

			if c.indexErr != nil {
				client.On("Index", mock.Anything, mock.Anything).Return(nil, c.indexErr)
			} else {
				imageIndex := v1fake.FakeImageIndex{}
				imageIndex.IndexManifestReturns(c.indexManifest, c.indexManifestErr)
				client.On("Index", mock.Anything, mock.Anything).Return(&imageIndex, nil)
			}

			if c.resolveErr != nil {
				client.On("ResolveDigest", mock.Anything).Return("", c.resolveErr)
			} else if c.resolvedDigest != "" {
				client.On("ResolveDigest", mock.Anything).Return(c.resolvedDigest, nil)
			}

			ctx := oci.WithClient(context.Background(), &client)
			bctx := rego.BuiltinContext{Context: ctx}

			got, _ := ociImageIndex(bctx, c.ref)

			if c.wantErr {
				require.Nil(t, got)
			} else {
				require.NotNil(t, got)
				snaps.MatchJSON(t, got)
			}
		})
	}
}

func TestFunctionsRegistered(t *testing.T) {
	names := []string{
		ociBlobName,
		ociDescriptorName,
		ociImageFilesName,
		ociImageManifestName,
		ociImageIndexName,
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			for _, builtin := range ast.Builtins {
				if builtin.Name == name {
					return
				}
			}
			t.Fatalf("%s builtin not registered", name)
		})
	}
}
