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

// This module is more of a general purpose wrapper for fetching files and
// saving them locally. It was originally used only for policy, i.e. rego and
// yaml files, from the policy repo, hence the name choice PolicySource,
// but now it's also used for fetching configuration from a git url.

package source

import (
	"context"
	"fmt"

	"github.com/conforma/go-gather/detector"
	log "github.com/sirupsen/logrus"
)

// SourceIsFile returns true if go-getter thinks the src looks like a file path.
// Ensuring that the src is not a git url is important because go-getter can think
// that a git url is a file path url.
func SourceIsFile(src string) bool {
	return detector.FileDetector(src)
}

// SourceIsGit returns true if go-getter thinks the src looks like a git url
func SourceIsGit(src string) bool {
	return detector.GitDetector(src)
}

// SourceIsHttp returns true if go-getter thinks the src looks like an http url
func SourceIsHttp(src string) bool {
	return detector.HttpDetector(src)
}

func GoGetterDownload(ctx context.Context, tmpDir, src string) (string, error) {
	// Download the config from a url
	c := PolicyUrl{
		Url:  src,
		Kind: ConfigKind,
	}
	configDir, err := c.GetPolicy(ctx, tmpDir, false)
	if err != nil {
		log.Debugf("Failed to download policy config from %s", c.Url)
		return "", err
	}
	log.Debugf("Downloaded policy config from %s to %s", c.Url, configDir)

	// Look for a suitable file to use for the config
	configFile, err := choosePolicyFile(ctx, configDir)
	if err != nil {
		// A more useful error message:
		return "", fmt.Errorf("no suitable config file found at %s", c.Url)
	}
	log.Debugf("Chose file %s to use for the policy config", configFile)
	return configFile, nil
}
