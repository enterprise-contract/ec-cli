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

package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/tektoncd/pipeline/pkg/remote/oci"

	"github.com/hacbs-contract/ec-cli/internal/image"
)

func Test_tektonBundleCollector(t *testing.T) {
	defaultFetchImage := fetchImage
	t.Cleanup(func() {
		fetchImage = defaultFetchImage
	})

	cases := []struct {
		name     string
		kinds    []string
		err      error
		expected []string
	}{
		{
			name: "failed to fetch image",
			err:  errors.New("expected"),
		},
		{
			name:     "a task and a pipeline",
			kinds:    []string{"task", "pipeline"},
			expected: []string{"task", "pipeline"},
		},
		{
			name:     "a few tasks",
			kinds:    []string{"task", "task"},
			expected: []string{"task"},
		},
		{
			name:     "a few pipelines",
			kinds:    []string{"pipeline", "pipeline", "pipeline"},
			expected: []string{"pipeline"},
		},
		{
			name:     "multiple tasks and multiple pipelines",
			kinds:    []string{"task", "pipeline", "pipeline", "task", "task"},
			expected: []string{"task", "pipeline"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fetchImage = func(name name.Reference, _ ...remote.Option) (v1.Image, error) {
				if c.err != nil {
					return nil, c.err
				}

				img := empty.Image

				var err error
				for _, k := range c.kinds {
					if img, err = mutate.Append(img, mutate.Addendum{
						Layer: static.NewLayer([]byte{}, types.OCILayer),
						Annotations: map[string]string{
							oci.KindAnnotation: k,
						},
					}); err != nil {
						return nil, err
					}
				}

				return img, nil
			}

			got, err := tektonBundleCollector(context.TODO(), image.ImageReference{})
			if c.err != nil {
				assert.Equal(t, c.err, err)
			} else {
				assert.NoError(t, err)
			}

			assert.ElementsMatch(t, c.expected, got)
		})
	}
}
