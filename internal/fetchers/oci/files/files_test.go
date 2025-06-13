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

package files

import (
	"archive/tar"
	"context"
	"encoding/json"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/utils/oci"
	"github.com/conforma/cli/internal/utils/oci/fake"
)

func TestImageManifests(t *testing.T) {
	ref := name.MustParseReference("registry.io/repository/image:tag")

	image, err := crane.Image(map[string][]byte{
		"autoexec.bat":              []byte(`@ECHO OFF`),
		"manifests/a.json":          []byte(`{"a":1}`),
		"manifests/b.yaml":          []byte(`b: 2`),
		"manifests/c.xml":           []byte(`<?xml version="1.0" encoding="UTF-8"?>`),
		"manifests/unreadable.yaml": []byte(`***`),
		"manifests/unreadable.json": []byte(`***`),
	})
	require.NoError(t, err)
	image, err = mutate.Config(image, v1.Config{
		Labels: map[string]string{
			olm_manifest_v1: "manifests/",
		},
	})
	require.NoError(t, err)

	client := fake.FakeClient{}
	client.On("Image", ref).Return(image, nil)

	ctx := oci.WithClient(context.Background(), &client)

	extractors := []Extractor{OLMManifest{}}
	files, err := ImageFiles(ctx, ref, extractors)

	assert.NoError(t, err)

	assert.Equal(t, map[string]json.RawMessage{
		"manifests/a.json": []byte(`{"a":1}`),
		"manifests/b.yaml": []byte(`{"b":2}`),
	}, files)
}

func TestDoesntFetchLayersForUnsupported(t *testing.T) {
	ref := name.MustParseReference("registry.io/repository/image:tag")

	image, err := mutate.Config(empty.Image, v1.Config{
		Labels: map[string]string{
			"hello": "label",
		},
	})
	require.NoError(t, err)

	client := fake.FakeClient{}
	client.On("Image", ref).Return(image, nil)

	ctx := oci.WithClient(context.Background(), &client)

	extractors := []Extractor{OLMManifest{}}
	files, err := ImageFiles(ctx, ref, extractors)

	assert.NoError(t, err)
	assert.Nil(t, files)

	client.AssertNotCalled(t, "Layers")
}

func TestCustomExtractor(t *testing.T) {
	ref := name.MustParseReference("registry.io/repository/image:tag")

	image, err := crane.Image(map[string][]byte{
		"autoexec.bat":              []byte(`@ECHO OFF`),
		"manifests/a.json":          []byte(`{"a":1}`),
		"manifests/b.yaml":          []byte(`b: 2`),
		"manifests/c.xml":           []byte(`<?xml version="1.0" encoding="UTF-8"?>`),
		"manifests/unreadable.yaml": []byte(`***`),
		"manifests/unreadable.json": []byte(`***`),
	})
	require.NoError(t, err)

	client := fake.FakeClient{}
	client.On("Image", ref).Return(image, nil)

	ctx := oci.WithClient(context.Background(), &client)

	extractors := []Extractor{PathExtractor{Path: "manifests"}}
	files, err := ImageFiles(ctx, ref, extractors)

	assert.NoError(t, err)

	assert.Equal(t, map[string]json.RawMessage{
		"manifests/a.json": []byte(`{"a":1}`),
		"manifests/b.yaml": []byte(`{"b":2}`),
	}, files)
}

func TestShouldFilter(t *testing.T) {
	cases := []struct {
		name     string
		matcher  PathMatcher
		header   *tar.Header
		decision bool
	}{
		{name: "nil"},
		{name: "nil header"},
		{name: "zero header", header: &tar.Header{}},
		{
			name:    "unrelated file",
			matcher: PathMatcher{"path"},
			header: &tar.Header{
				Name: "autoexec.bat",
			},
		},
		{
			name:    "not in considered path",
			matcher: PathMatcher{"one/"},
			header: &tar.Header{
				Name: "else/manifest.json",
			},
		},
		{
			name:    "unsupported extension",
			matcher: PathMatcher{"manifests/"},
			header: &tar.Header{
				Name: "manifests/autoexec.bat",
			},
		},
		{
			name:    "happy day",
			matcher: PathMatcher{"manifests/"},
			header: &tar.Header{
				Name: "manifests/something.json",
			},
			decision: true,
		},
		{
			name:    "happy day - no trailing slash",
			matcher: PathMatcher{"manifests"},
			header: &tar.Header{
				Name: "manifests/something.json",
			},
			decision: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			decision := c.matcher.Match(c.header)
			assert.Equal(t, c.decision, decision)
		})
	}
}
