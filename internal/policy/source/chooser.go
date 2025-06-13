// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"
	"fmt"
	"path"

	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/utils"
)

var policyFileBaseNames = []string{
	".ec/policy",
	"policy",
}

var policyFileExtensions = []string{
	"json",
	"yaml",
	"yml",
}

// choosePolicyFile picks a file from a given directory to use as an Conforma policy file
// Uses policyFileBaseNames and policyFileExtensions to decide what to look for
func choosePolicyFile(ctx context.Context, configDir string) (string, error) {
	fs := utils.FS(ctx)
	for _, b := range policyFileBaseNames {
		for _, e := range policyFileExtensions {
			configFile := path.Join(configDir, fmt.Sprintf("%s.%s", b, e))
			fileExists, err := afero.Exists(fs, configFile)
			if err != nil {
				return "", err
			}
			if fileExists {
				return configFile, nil
			}
		}
	}
	return "", fmt.Errorf("no suitable config file found in %s", configDir)
}
