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

package source

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/hacbs-contract/ec-cli/internal/downloader"
)

// For testing purposes
var DownloadPolicy = downloader.DownloadPolicy
var DownloadData = downloader.DownloadData

//PolicySource in an interface representing the location of policies.
//Must implement the GetPolicies() method.
type PolicySource interface {
	GetPolicies(ctx context.Context, dest string, showMsg bool) error
}

//PolicyUrl is a string containing a go-getter style source url compatible with conftest pull
type PolicyUrl string

// Define additional sources that will always be fetched
func HardCodedSources() []PolicySource {
	sources := []PolicySource{}

	repoUrls := []string{
		// There are two important data files in this directory
		"git::https://github.com/hacbs-contract/ec-policies//data",
	}

	for _, r := range repoUrls {
		repo := PolicyUrl(r)
		sources = append(sources, &repo)
	}

	return sources
}

// GetPolicies clones the repository for a given PolicyUrl
func (p *PolicyUrl) GetPolicies(ctx context.Context, dest string, showMsg bool) error {
	sourceUrl := string(*p)

	// Checkout policy repo into work directory.
	log.Debugf("Downloading from source url %s to work dir at %s", sourceUrl, dest)

	if downloader.ProbablyDataSource(sourceUrl) {
		// Special handling: Download it to the data directory instead Todo:
		// This should be replaced by a more robust way to distinguish between
		// "data" sources and "policy" sources. Doing it this way now so we
		// don't need to depend on changes to the types imported from the ecc
		// package. (In future we might have a v1alpha1.GitDataSource to go
		// with v1alpha1.GitPolicySource in future, or something similar.)
		return DownloadData(ctx, dest, sourceUrl, showMsg)
	} else {
		// Download it to the policy directory as per usual
		return DownloadPolicy(ctx, dest, sourceUrl, showMsg)
	}

}
