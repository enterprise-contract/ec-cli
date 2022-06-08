/*
Copyright © 2022 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package policy

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	ecp "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func Test_fetchPolicyDataEmptySpec(t *testing.T) {
	datadir, err := fetchPolicyData(ecp.EnterpriseContractPolicySpec{})
	defer os.RemoveAll(datadir)

	assert.NoError(t, err)

	configJSONPath := path.Join(datadir, "config.json")

	assert.FileExists(t, configJSONPath, "config.json should have been created in %s", datadir)

	configJSON, err := os.Open(configJSONPath)
	assert.NoError(t, err)
	defer configJSON.Close()

	data, err := ioutil.ReadAll(configJSON)
	assert.NoError(t, err)

	assert.JSONEq(t, string(data), "{}", "expecting empty config.json")
}

func Test_fetchPolicyDataWithExceptions(t *testing.T) {
	datadir, err := fetchPolicyData(ecp.EnterpriseContractPolicySpec{
		Exceptions: &ecp.EnterpriseContractPolicyExceptions{
			NonBlocking: []string{
				"a",
				"b",
				"c",
			},
		},
	})
	defer os.RemoveAll(datadir)

	assert.NoError(t, err)

	configJSONPath := path.Join(datadir, "config.json")

	assert.FileExists(t, configJSONPath, "config.json should have been created in %s", datadir)

	configJSON, err := os.Open(configJSONPath)
	assert.NoError(t, err)
	defer configJSON.Close()

	data, err := ioutil.ReadAll(configJSON)
	assert.NoError(t, err)

	assert.JSONEq(t, string(data), `{
		"config": {
			"policy": {
				"non_blocking_checks": [ "a", "b", "c" ]
			}
		}
	}`, "expecting config.json with non blocking a, b and c")
}
