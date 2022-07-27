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

package replacer

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLatestVersion(t *testing.T) {
	cases := []struct {
		name            string
		resourceName    string
		resourceKind    string
		catalogName     string
		responseStatus  int
		responseContent string
		responseError   error
		expectedVersion string
		expectedError   string
	}{
		{
			name:            "success",
			resourceName:    "my-task",
			resourceKind:    "task",
			catalogName:     "my-catalog",
			responseStatus:  200,
			responseContent: `{"data": {"latestVersion": {"version": "4.0"}}}`,
			expectedVersion: "4.0",
		},
		{
			name:            "invalid json",
			resourceName:    "my-task",
			resourceKind:    "task",
			catalogName:     "my-catalog",
			responseStatus:  200,
			responseContent: `"data": {"latestVersion": {"version": "4.0"}}}`,
			expectedError:   "invalid character ':' after top-level value",
		},
		{
			name:           "bad api response",
			resourceName:   "my-task",
			resourceKind:   "task",
			catalogName:    "my-catalog",
			responseStatus: 500,
			responseError:  errors.New("uh oh"),
			expectedError:  "uh oh",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hubHttpGet = func(url string) (*http.Response, error) {
				expectedUrl := fmt.Sprintf(
					"https://api.example.com/v1/resource/%s/%s/%s",
					c.catalogName, c.resourceKind, c.resourceName)
				assert.Equal(t, expectedUrl, url)
				body := ioutil.NopCloser(bytes.NewReader([]byte(c.responseContent)))
				return &http.Response{
					StatusCode: c.responseStatus,
					Body:       body,
				}, c.responseError
			}
			client := hubClient{url: "https://api.example.com"}
			got, err := client.latestVersion(c.resourceName, c.resourceKind, c.catalogName)
			if c.expectedError != "" {
				assert.ErrorContains(t, err, c.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.expectedVersion, got)
			}
		})
	}
}
