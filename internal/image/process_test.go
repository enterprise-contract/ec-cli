// Copyright 2022 Red Hat, Inc.
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

package image

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
)

var testHash = v1.Hash{
	Algorithm: "sha256",
	Hex:       "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
}

// func ParseAndResolveAll(urls []string) ([]ImageReference, error) {
func TestParseAndResolveAll(t *testing.T) {
	tests := []struct {
		name       string
		urls       []string
		refs       []ImageReference
		err        string
		headDigest v1.Hash
	}{
		{
			name: "url contains tag and digest",
			urls: []string{
				"registry.com/repo:one@" + testHash.String(),
			},
			refs: []ImageReference{
				{
					Repository: "registry.com/repo",
					Digest:     testHash.String(),
					Tag:        "one",
				},
			},
		},
		{
			name: "url contains only tag",
			urls: []string{
				"registry.com/repo:one",
			},
			refs: []ImageReference{
				{
					Repository: "registry.com/repo",
					Digest:     testHash.String(),
					Tag:        "one",
				},
			},
			headDigest: testHash,
		},
		{
			name: "url contains only digest",
			urls: []string{
				"registry.com/repo@" + testHash.String(),
			},
			refs: []ImageReference{
				{
					Repository: "registry.com/repo",
					Digest:     testHash.String(),
					Tag:        "",
				},
			},
		},
		{
			name: "errors are collected for each url",
			urls: []string{
				// Incomplete digest
				"registry.com/one@sha256:123",
				// Bad registry host
				"registry/two@" + testHash.String(),
				// Missing repo
				"three.com@" + testHash.String(),
				// But this one should cause no errors
				"registry.com/repo:good@" + testHash.String(),
			},
			err: "3 errors occurred",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// func Head(ref name.Reference, options ...Option) (*v1.Descriptor, error) {
			remoteHead = func(ref name.Reference, options ...remote.Option) (*v1.Descriptor, error) {
				// Ensure it is only called when expected.
				assert.NotEmpty(t, tt.headDigest)
				return &v1.Descriptor{Digest: tt.headDigest}, nil
			}
			refs, err := ParseAndResolveAll(tt.urls)
			if tt.err != "" {
				assert.ErrorContains(t, err, tt.err)
				return
			}
			assert.NoError(t, err)
			// Ignore exact match of the internal state
			for i := 0; i < len(refs); i++ {
				refs[i].ref = nil
			}
			assert.Equal(t, tt.refs, refs)
		})
	}
}

func TestImageReferenceString(t *testing.T) {
	cases := []struct {
		name     string
		ref      ImageReference
		expected string
	}{
		{
			name: "repository only",
			ref: ImageReference{
				Repository: "repository.com/repo",
			},
			expected: "repository.com/repo",
		},
		{
			name: "digest only",
			ref: ImageReference{
				Repository: "repository.com/repo",
				Digest:     testHash.String(),
			},
			expected: "repository.com/repo@" + testHash.String(),
		},
		{
			name: "tag only",
			ref: ImageReference{
				Repository: "repository.com/repo",
				Tag:        "1.0",
			},
			expected: "repository.com/repo:1.0",
		},
		{
			name: "both digest and tag",
			ref: ImageReference{
				Repository: "repository.com/repo",
				Digest:     testHash.String(),
				Tag:        "1.0",
			},
			expected: "repository.com/repo:1.0@" + testHash.String(),
		},
	}

	for _, c := range cases {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, c.expected, c.ref.String())
		})
	}
}
