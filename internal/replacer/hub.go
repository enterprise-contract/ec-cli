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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// hubClient interacts with the Tekton Hub API.
type hubClient struct {
	url string
}

// hubHttpGet makes it easier to write hermetic unit tests.
var hubHttpGet = http.Get

// latestVersion returns the lates version of the given resource
// querying the Tekton Hub API.
func (c *hubClient) latestVersion(name string, kind string, catalog string) (version string, err error) {
	url := fmt.Sprintf("%s/v1/resource/%s/%s/%s", c.url, catalog, kind, name)
	resp, err := hubHttpGet(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resource := hubResource{}
	err = json.Unmarshal(body, &resource)
	if err != nil {
		return
	}
	version = resource.Data.LatestVersion.Version
	return
}

// tektonCatalogResource assists parsing the resource representation
// returned by the Tekton Hub API.
type hubResource struct {
	Data struct {
		LatestVersion struct {
			Version string `json:"version"`
		} `json:"latestVersion"`
	} `json:"data"`
}
