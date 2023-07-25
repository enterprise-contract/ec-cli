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

package oci

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type key string

const clientKey key = "ec.fetcher.config.client"

type client interface {
	Image(name.Reference, ...remote.Option) (v1.Image, error)
}

func NewClient(ctx context.Context) client {
	c, ok := ctx.Value(clientKey).(client)
	if ok && c != nil {
		return c
	}

	return &remoteClient{}
}

func WithClient(ctx context.Context, c client) context.Context {
	return context.WithValue(ctx, clientKey, c)
}

type remoteClient struct {
}

func (*remoteClient) Image(ref name.Reference, opts ...remote.Option) (v1.Image, error) {
	return remote.Image(ref, opts...)
}
