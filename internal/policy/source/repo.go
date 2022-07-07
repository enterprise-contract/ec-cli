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
	"fmt"
	"net/url"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"
)

//CheckoutRepo is used as an alias for git.PlainClone in order to facilitate testing
var CheckoutRepo = git.PlainClone

//PolicySource in an interface representing the location of policies.
//Must implement the GetPolicies() and GetPolicyDir() methods.
type PolicySource interface {
	GetPolicies(dest string) error
	GetPolicyDir() string
}

//PolicyRepo is a struct representing a repository storing policy data.
type PolicyRepo struct {
	PolicyDir string
	RepoURL   string
	RepoRef   string
}

// GetPolicyDir returns the policy directory for a given PolicyRepo
func (p *PolicyRepo) GetPolicyDir() string {
	return p.PolicyDir
}

// GetPolicies clones the repository for a given PolicyRepo
func (p *PolicyRepo) GetPolicies(dest string) error {
	// Checkout policy repo into work directory.
	log.Debugf("Checking out repo %s at %s to work dir", p.RepoURL, p.RepoRef)
	_, err := CheckoutRepo(dest, false, &git.CloneOptions{
		URL:           p.RepoURL,
		Progress:      nil,
		SingleBranch:  true,
		ReferenceName: plumbing.NewBranchReferenceName(p.RepoRef),
	})
	return err
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

// CreatePolicyRepoFromSource parses a v1alpha1.GitPolicySource into a PolicyRepo struct
func CreatePolicyRepoFromSource(s v1alpha1.GitPolicySource) (PolicyRepo, error) {
	log.Debug("Creating policy repo from git policy source")

	u, policyDir, err := normalizeRepoUrl(s.Repository)
	if err != nil {
		return PolicyRepo{}, err
	}

	if s.Revision != nil {
		return PolicyRepo{
			PolicyDir: policyDir,
			RepoURL:   u,
			RepoRef:   *s.Revision,
		}, nil
	}

	// query to get the head then we'll plug this in
	ref, err := getRepoHeadRef(u)
	if err != nil {
		return PolicyRepo{}, err
	}

	return PolicyRepo{
		PolicyDir: policyDir,
		RepoURL:   u,
		RepoRef:   *ref,
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
	if len(splitPath) == 3 {
		s = fmt.Sprintf("%s://%s/%s/%s.git", u.Scheme, u.Host, user, repo)
		policyDir = splitPath[2]
	} else {
		s = fmt.Sprintf("%s://%s/%s/%s", u.Scheme, u.Host, user, repo)
		//policyDir = "policy"
	}
	log.Debugf("Normalized git repo url and policyDir %s %s", s, policyDir)
	return s, policyDir, nil
}
