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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

// Determine policyConfig
func GetPolicyConfig(ctx context.Context, policyConfiguration string) (string, error) {
	// Check if policyConfiguration is a git url. If so, try to download a config file from git.
	// If successful we write that into the data.policyConfiguration var.
	if source.SourceIsGit(policyConfiguration) {
		log.Debugf("Fetching policy config from git url %s", policyConfiguration)

		// Create a temporary dir to download the config. This is separate from the workDir usd
		// later for downloading policy sources, but it doesn't matter because this dir is not
		// used again once the config file has been read.
		fs := utils.FS(ctx)
		tmpDir, err := utils.CreateWorkDir(fs)
		if err != nil {
			return "", err
		}
		defer utils.CleanupWorkDir(fs, tmpDir)

		// Git download and find a suitable config file
		configFile, err := source.GitConfigDownload(ctx, tmpDir, policyConfiguration)
		if err != nil {
			return "", err
		}

		// Changing data.policyConfiguration to the name of the newly downloaded file means we can
		// use the code below to load the config
		policyConfiguration = configFile
	}

	// Check if policyConfig is a file path. If so, try to read it. If successful we write
	// that into the data.policyConfiguration var.
	if utils.HasJsonOrYamlExt(policyConfiguration) {
		fs := utils.FS(ctx)
		policyBytes, err := afero.ReadFile(fs, policyConfiguration)
		if err != nil {
			return "", err
		}
		// Check for empty file as that would cause a false "success"
		if len(policyBytes) == 0 {
			err := fmt.Errorf("file %s is empty", policyConfiguration)
			return "", err
		}
		log.Debugf("Loaded %s as policyConfiguration", policyConfiguration)
		policyConfiguration = string(policyBytes)
	}
	return policyConfiguration, nil

}
