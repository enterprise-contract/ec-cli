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
	"fmt"
	"net/url"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"

	"github.com/hacbs-contract/ec-cli/internal/downloader"
)

// For testing purposes
var DownloadPolicy = downloader.DownloadPolicy
var DownloadData = downloader.DownloadData

//PolicySource in an interface representing the location of policies.
//Must implement the GetPolicies() and GetPolicyDir() methods.
type PolicySource interface {
	GetPolicies(ctx context.Context, dest string, showMsg bool) error
	GetPolicyDir() string
}

//PolicyRepo is a struct representing a repository storing policy data.
type PolicyRepo struct {
	RawSourceURL string
	PolicyDir    string
	RepoURL      string
	RepoRef      string
}

// Define additional sources that will always be fetched
func HardCodedSources() []PolicySource {
	sources := []PolicySource{}

	repoUrls := []string{
		// There are two important data files in this directory
		"https://github.com/hacbs-contract/ec-policies/data",
	}

	for _, r := range repoUrls {
		repo, err := CreatePolicyRepoFromRepoAndRevision(r, "")
		if err != nil {
			panic(err)
		}
		sources = append(sources, &repo)
	}

	return sources
}

// GetPolicyDir returns the policy directory for a given PolicyRepo
func (p *PolicyRepo) GetPolicyDir() string {
	return p.PolicyDir
}

// GetPolicies clones the repository for a given PolicyRepo
func (p *PolicyRepo) GetPolicies(ctx context.Context, dest string, showMsg bool) error {
	// Checkout policy repo into work directory.
	log.Debugf("Checking out repo %s at %s to work dir at %s", p.RepoURL, p.RepoRef, dest)

	var sourceUrl string
	if downloader.ProbablyGoGetterFormat(p.RawSourceURL) {
		// Assume the raw source url is a valid go getter url.
		// Ignore the other fields and use it directly.
		sourceUrl = p.RawSourceURL

	} else {
		// Create a go-getter url from the fields prepared earlier in
		// source.CreatePolicyRepoFromSource
		sourceUrl = downloader.GetterGitUrl(p.RepoURL, p.PolicyDir, p.RepoRef)
	}

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

// getRepoHeadRef gets the default head reference for a given git URL
func getRepoHeadRef(repoURL string) (*string, error) {
	//set p.RepoRef
	e, err := transport.NewEndpoint(repoURL)
	if err != nil {
		log.Debugf("Problem creating end point for git!")
		return nil, err
	}
	cli, err := client.NewClient(e)
	if err != nil {
		log.Debugf("Problem creating git client!")
		return nil, err
	}
	s, err := cli.NewUploadPackSession(e, nil)
	if err != nil {
		log.Debugf("Problem creating git session!")
		return nil, err
	}
	info, err := s.AdvertisedReferences()
	if err != nil {
		log.Debugf("Problem finding git reference details!")
		return nil, err
	}
	refs, err := info.AllReferences()
	if err != nil {
		log.Debugf("Problem fetching git references!")
		return nil, err
	}
	var r = refs["HEAD"].Target().Short()
	log.Debugf("Found head ref %s", r)
	return &r, nil
}

// CreatePolicyRepoFromSource parses a ecc.GitPolicySource into a PolicyRepo struct
func CreatePolicyRepoFromSource(s ecc.GitPolicySource) (PolicyRepo, error) {
	return CreatePolicyRepoFromRepoAndRevision(s.Repository, s.Revision)
}

func CreatePolicyRepoFromRepoAndRevision(repository string, revision string) (PolicyRepo, error) {
	log.Debug("Creating policy repo from git policy source")

	// Normalize the url, extract the policyDir if there is one, and determine the ref to use
	u, policyDir, err := normalizeRepoUrl(repository)
	if err != nil {
		return PolicyRepo{}, err
	}

	if revision != "" {
		return PolicyRepo{
			RawSourceURL: repository,
			PolicyDir:    policyDir,
			RepoURL:      u,
			RepoRef:      revision,
		}, nil
	}

	// query to get the head then we'll plug this in
	ref, err := getRepoHeadRef(u)
	if err != nil {
		return PolicyRepo{}, err
	}

	return PolicyRepo{
		RawSourceURL: repository,
		PolicyDir:    policyDir,
		RepoURL:      u,
		RepoRef:      *ref,
	}, nil
}

// normalizeRepoUrl checks if a given URL string has a scheme (https or http),
// if it ends in '.git' or if it includes the policy directory
func normalizeRepoUrl(s string) (string, string, error) {
	s = func(repoUrl string) string {
		u, _ := url.Parse(repoUrl)
		if len(u.Scheme) == 0 {
			repoUrl = fmt.Sprintf("https://%s", repoUrl)
		}
		return repoUrl
	}(s)
	u, err := url.Parse(s)
	if err != nil {
		log.Debugf("Problem parsing git repo url %s", s)
		return "", "", err
	}
	path := strings.TrimLeft(u.Path, "/")
	splitPath := strings.Split(path, "/")
	user := splitPath[0]
	repo := splitPath[1]
	var policyDir string
	if len(splitPath) >= 3 {
		s = fmt.Sprintf("%s://%s/%s/%s.git", u.Scheme, u.Host, user, repo)
		policyDir = strings.Join(splitPath[2:], "/")
	} else {
		s = fmt.Sprintf("%s://%s/%s/%s", u.Scheme, u.Host, user, repo)
		//policyDir = "policy"
	}
	log.Debugf("Normalized git repo url and policyDir %s %s", s, policyDir)
	return s, policyDir, nil
}
