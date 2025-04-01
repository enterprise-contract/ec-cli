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
	"errors"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplicableTo(t *testing.T) {
	emptyConfig, err := mutate.Config(empty.Image, v1.Config{})
	require.NoError(t, err)

	someLabel, err := mutate.Config(empty.Image, v1.Config{
		Labels: map[string]string{"x": "y"},
	})
	require.NoError(t, err)

	olmPath, err := mutate.Config(empty.Image, v1.Config{
		Labels: map[string]string{olm_manifest_v1: "path/"},
	})
	require.NoError(t, err)

	olmDifferent, err := mutate.Config(empty.Image, v1.Config{
		Labels: map[string]string{olm_manifest_v1: "different/"},
	})
	require.NoError(t, err)

	boom := errors.New("boom")
	blowsUp := fake.FakeImage{}
	blowsUp.ConfigFileReturns(nil, boom)

	paths := []string{"path/a.json"}
	differents := []string{"different/a.yaml"}
	cases := []struct {
		name     string
		img      v1.Image
		err      error
		positive []string
		negative []string
	}{
		{name: "nil"},
		{name: "empty", img: empty.Image},
		{name: "empty config", img: emptyConfig},
		{name: "unrelated labels", img: someLabel},
		{name: "OLM manifest label", img: olmPath, positive: paths, negative: differents},
		{name: "OLM manifest label different path", img: olmDifferent, positive: differents, negative: paths},
		{name: "error case", img: &blowsUp, err: boom},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matcher, err := OLMManifest{}.Matcher(c.img)
			if c.err == nil {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, c.err, err)
			}

			if matcher == nil && len(c.positive) > 0 && len(c.negative) > 0 {
				assert.NotNil(t, matcher)
			}

			for _, p := range c.positive {
				assert.True(t, matcher(&tar.Header{Name: p}), p)
			}

			for _, n := range c.negative {
				assert.False(t, matcher(&tar.Header{Name: n}), n)
			}
		})
	}
}
