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

package policy

import (
	"encoding/json"
	"os"
	"path"

	ecp "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
)

func fetchPolicyData(spec ecp.EnterpriseContractPolicySpec) (string, error) {
	config := map[string]interface{}{}

	if spec.Exceptions != nil {
		config["config"] = map[string]interface{}{
			"policy": map[string]interface{}{
				"non_blocking_checks": spec.Exceptions.NonBlocking,
			},
		}
	}

	datadir, err := os.MkdirTemp("", "ecp_data.*")
	if err != nil {
		return "", err
	}

	f, err := os.Create(path.Join(datadir, "config.json"))
	if err != nil {
		return "", err
	}
	defer f.Close()

	j := json.NewEncoder(f)
	if err = j.Encode(config); err != nil {
		return "", err
	}

	return datadir, nil
}
