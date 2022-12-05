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

package replacer

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/image"
)

const testHash = "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"

func TestBasicImageReplacer(t *testing.T) {
	cases := []struct {
		name          string
		url           string
		inputLine     string
		expectedMatch bool
		expectedLine  string
	}{
		{
			name:          "replace when matched",
			url:           "registry.com/bundles/my-task:4.0",
			expectedMatch: true,
			inputLine:     "taskRef: registry.com/bundles/my-task:3.0",
			expectedLine:  "taskRef: registry.com/bundles/my-task:4.0",
		},
		{
			name:          "no replacement when not matched",
			url:           "registry.com/bundles/my-task:4.0",
			expectedMatch: false,
			inputLine:     "taskRef: registry.com/other-bundles/my-task:3.0",
			expectedLine:  "taskRef: registry.com/other-bundles/my-task:3.0",
		},
		{
			name:          "metacharacters are escaped",
			url:           "registry.com/bundles/my-task:4.0",
			expectedMatch: false,
			inputLine:     "taskRef: registryXcom/bundles/my-task:3.0",
			expectedLine:  "taskRef: registryXcom/bundles/my-task:3.0",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ref, err := image.NewImageReference(c.url, name.StrictValidation)
			assert.NoError(t, err)
			replacer, err := newBasicImageReplacer(*ref)
			assert.NoError(t, err)
			line := []byte(c.inputLine)
			assert.Equal(t, c.expectedMatch, replacer.match(line))
			assert.Equal(t, c.expectedLine, string(replacer.replace(line)))
		})
	}
}

func TestCatalogImageReplacer(t *testing.T) {
	cases := []struct {
		name          string
		latestVersion string
		inputLine     string
		expectedMatch bool
		expectedLine  string
	}{
		{
			name:          "replace when matched",
			latestVersion: "4.0",
			inputLine:     "taskRef: registry.com/bundles/my-task:3.0",
			expectedMatch: true,
			expectedLine:  "taskRef: registry.com/bundles/my-task:4.0@" + testHash,
		},
		{
			name:          "no replacement when not matched",
			inputLine:     "taskRef: registry.com/other-bundles/my-task:3.0",
			expectedMatch: false,
			expectedLine:  "taskRef: registry.com/other-bundles/my-task:3.0",
		},
		{
			name:          "metacharacters are escaped",
			latestVersion: "4.0",
			inputLine:     "taskRef: registryXcom/bundles/my-task:3.0",
			expectedMatch: false,
			expectedLine:  "taskRef: registryXcom/bundles/my-task:3.0",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hubHttpGet = func(url string) (*http.Response, error) {
				content := `{"data": {"latestVersion": {"version": "` + c.latestVersion + `"}}}`
				body := io.NopCloser(bytes.NewReader([]byte(content)))
				return &http.Response{
					StatusCode: 200,
					Body:       body,
				}, nil
			}
			imageParseAndResolve = func(url string, _ ...name.Option) (*image.ImageReference, error) {
				// Adding a digest makes it so the real image.ParseAndResolve doesn't make
				// a network connection.
				return image.ParseAndResolve(url + "@" + testHash)
			}

			replacer, err := newCatalogImageReplacer(&CatalogOptions{
				CatalogName: "tekton",
				RepoBase:    "registry.com/bundles/",
				HubAPIURL:   "https://api.example.com",
			})
			assert.NoError(t, err)
			line := []byte(c.inputLine)
			assert.Equal(t, c.expectedMatch, replacer.match(line))
			assert.Equal(t, c.expectedLine, string(replacer.replace(line)))
		})
	}
}
