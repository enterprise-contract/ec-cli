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

package oci

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheInit(t *testing.T) {
	// by default the cache should be on
	assert.NotNil(t, initCache())

	t.Setenv("EC_CACHE", "false")
	assert.Nil(t, initCache())

	t.Cleanup(func() {
		t.Setenv("EC_CACHE", "true")
		assert.NotNil(t, initCache())
	})
}

func TestImage(t *testing.T) {
	img, err := random.Image(4096, 2)
	require.NoError(t, err)

	l := &bytes.Buffer{}
	registry := httptest.NewServer(registry.New(registry.Logger(log.New(l, "", 0))))
	t.Cleanup(registry.Close)

	u, err := url.Parse(registry.URL)
	require.NoError(t, err)

	ref, err := name.ParseReference(fmt.Sprintf("localhost:%s/repository/image:tag", u.Port()))
	require.NoError(t, err)

	require.NoError(t, remote.Put(ref, img))

	fetchFully := func() {
		img, err := defaultClient.Image(ref)
		require.NoError(t, err)
		layers, err := img.Layers()
		require.NoError(t, err)
		for _, l := range layers {
			r, err := l.Uncompressed()
			require.NoError(t, err)
			_, err = io.ReadAll(r)
			require.NoError(t, err)
		}
	}

	fetchFully()
	fetchFully()
	fetchFully()

	blobDownloadCount := strings.Count(l.String(), "GET /v2/repository/image/blobs/sha256:")
	assert.Equal(t, 5, blobDownloadCount) // three configs fetched each time and two layers fetched only once
}

func TestLayer(t *testing.T) {
	layer, err := random.Layer(1024, types.OCIUncompressedLayer)
	require.NoError(t, err)

	l := &bytes.Buffer{}
	registry := httptest.NewServer(registry.New(registry.Logger(log.New(l, "", 0))))
	t.Cleanup(registry.Close)

	u, err := url.Parse(registry.URL)
	require.NoError(t, err)

	uri := fmt.Sprintf("localhost:%s/repository/image", u.Port())
	repo, err := name.NewRepository(uri)
	require.NoError(t, err)

	require.NoError(t, remote.WriteLayer(repo, layer))

	digest, err := layer.Digest()
	require.NoError(t, err)
	layerURI := fmt.Sprintf("%s@%s", uri, digest)

	fetchCount := 5
	for i := 0; i < fetchCount; i++ {
		d, err := name.NewDigest(layerURI)
		require.NoError(t, err)
		l, err := defaultClient.Layer(d)
		require.NoError(t, err)
		r, err := l.Uncompressed()
		require.NoError(t, err)
		_, err = io.ReadAll(r)
		require.NoError(t, err)
	}

	msg := fmt.Sprintf("GET /v2/repository/image/blobs/%s", digest)
	blobDownloadCount := strings.Count(l.String(), msg)
	assert.Equal(t, fetchCount, blobDownloadCount)
}
