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

package files

import (
	"archive/tar"
	"errors"
	"fmt"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/stretchr/testify/require"
)

func TestRedHatManifest(t *testing.T) {
	malformedImage := fake.FakeImage{}
	kaboom := errors.New("kaboom!")
	malformedImage.ConfigFileReturns(nil, kaboom)

	matchingPaths := []string{
		fmt.Sprintf("%s/sbom-purl.json", redHatManifestPath),
		fmt.Sprintf("%s/sbom-cyclonedx.json", redHatManifestPath),
	}

	allPaths := append(matchingPaths,
		"path/sbom-purl.json",
		fmt.Sprintf("nested/%s/sbom-cyclonedx.json", redHatManifestPath),
		fmt.Sprintf("%ssbom.json", redHatManifestPath),
	)

	cases := []struct {
		name     string
		img      v1.Image
		err      error
		expected []string
	}{
		{name: "nil"},
		{name: "empty image", img: empty.Image},
		{name: "empty config", img: mustCreateImage(v1.Config{})},
		{name: "missing vendor label", img: mustCreateImage(v1.Config{
			Labels: map[string]string{"x": "y"},
		})},
		{name: "Red Hat image", img: mustCreateImage(v1.Config{
			Labels: map[string]string{redHatVendorLabelName: redHatVendorLabelValue},
		}), expected: matchingPaths},
		{name: "Non Red Hat image", img: mustCreateImage(v1.Config{
			Labels: map[string]string{redHatVendorLabelName: "Pink Scarf, Inc."},
		})},
		{name: "malformed image", img: &malformedImage, err: kaboom},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matcher, err := RedHatManifest{}.Matcher(c.img)
			if c.err != nil {
				require.Equal(t, c.err, err)
				require.Nil(t, matcher)
			} else {
				require.NoError(t, err)
			}
			if len(c.expected) == 0 {
				require.Nil(t, matcher)
				return
			}

			var actual []string
			for _, p := range allPaths {
				if matcher(&tar.Header{Name: p}) {
					actual = append(actual, p)
				}
			}
			require.Equal(t, c.expected, actual)
		})
	}
}

func mustCreateImage(cfg v1.Config) v1.Image {
	image, err := mutate.Config(empty.Image, cfg)
	if err != nil {
		panic(err)
	}
	return image
}
