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

package oci

import (
	"context"
	"fmt"
	"os"
	"path"
	"strconv"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	log "github.com/sirupsen/logrus"
)

type key string

const clientKey key = "ec.fetcher.config.client"

var imgCache cache.Cache

func init() {
	initCache()
}

func initCache() {
	// if a value was set and it is parsed as false, turn the cache off
	if v, err := strconv.ParseBool(os.Getenv("EC_CACHE")); err == nil && !v {
		return
	}

	if userCache, err := os.UserCacheDir(); err != nil {
		log.Debug("unable to find user cache directory")
	} else {
		imgCacheDir := path.Join(userCache, "ec", "images")
		if err := os.MkdirAll(imgCacheDir, 0700); err != nil {
			log.Debugf("unable to create temporary directory for image cache in %q: %v", imgCacheDir, err)
		}
		log.Debugf("using %q directory to store image cache", imgCacheDir)
		imgCache = cache.NewFilesystemCache(imgCacheDir)
	}
}

type client interface {
	Image(name.Reference, ...remote.Option) (v1.Image, error)
	Layer(name.Digest, ...remote.Option) (v1.Layer, error)
}

var defaultClient = remoteClient{}

func NewClient(ctx context.Context) client {
	c, ok := ctx.Value(clientKey).(client)
	if ok && c != nil {
		return c
	}

	return &defaultClient
}

func WithClient(ctx context.Context, c client) context.Context {
	return context.WithValue(ctx, clientKey, c)
}

type remoteClient struct {
}

func (*remoteClient) Image(ref name.Reference, opts ...remote.Option) (v1.Image, error) {
	img, err := remote.Image(ref, opts...)
	if err != nil {
		return nil, err
	}

	if imgCache != nil {
		img = cache.Image(img, imgCache)
	}

	return img, nil
}

func (*remoteClient) Layer(ref name.Digest, options ...remote.Option) (v1.Layer, error) {
	// TODO: Caching a layer directly is difficult and may not be possible, see:
	//   https://github.com/google/go-containerregistry/issues/1821
	layer, err := remote.Layer(ref, options...)
	if err != nil {
		return nil, fmt.Errorf("fetching layer: %w", err)
	}
	return layer, nil
}
