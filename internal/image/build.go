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

package image

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
)

type invocation struct {
	ConfigSource map[string]interface{} `json:"configSource"`
	Parameters   map[string]string      `json:"parameters"`
	Environment  map[string]interface{} `json:"environment"`
}

type predicate struct {
	Invocation  invocation               `json:"invocation"`
	BuildType   string                   `json:"buildType"`
	Metadata    map[string]interface{}   `json:"metadata"`
	Builder     map[string]interface{}   `json:"builder"`
	BuildConfig map[string]interface{}   `json:"buildConfig"`
	Materials   []map[string]interface{} `json:"materials"`
}

type attestation struct {
	Predicate     predicate                `json:"predicate"`
	PredicateType string                   `json:"predicateType"`
	Subject       []map[string]interface{} `json:"subject"`
	Type          string                   `json:"_type"`
}

type buildSigner interface {
	GetBuildSignOff() (*signOffSignature, error)
}

type commitSignoffSource struct {
	source    string
	commitSha string
}

type jiraSignoffSource struct {
	source string
	jiraid string
}

type tagSignoffSource struct {
	source    string
	tag       string
	commitSha string
}

type signOffSignature struct {
	Payload interface{} `json:"payload"`
	Source  string      `json:"source"`
}

// mocking
type sourceRepository interface {
	getRepository(string) (*git.Repository, error)
}

// From an attestation, find the signOff source (commit, tag, jira)
func (a *attestation) AttestationSignoffSource() (buildSigner, error) {
	// the signoff source can be determined by looking into the attestation.
	// the attestation can have an env var or something that this can key off of

	// A tag is the preferred sign off method, then the commit, then jira
	tag := a.getBuildTag()
	commitSha := a.getBuildCommitSha()

	if tag != "" && commitSha != "" {
		return &tagSignoffSource{
			source:    a.getBuildSCM(),
			tag:       tag,
			commitSha: commitSha,
		}, nil
	}

	if commitSha != "" {
		return &commitSignoffSource{
			source:    a.getBuildSCM(),
			commitSha: commitSha,
		}, nil
	}

	return nil, nil
}

// get the last commit used for the component build
func (a *attestation) getBuildCommitSha() string {
	return a.Predicate.Invocation.Parameters["revision"]
}

// the git url used for the component build
func (a *attestation) getBuildSCM() string {
	return a.Predicate.Invocation.Parameters["git-url"]
}

// if the component repo was tagged, get the tag from the attestation
func (a *attestation) getBuildTag() string {
	return a.Predicate.Invocation.Parameters["tag"]
}

// clone the repo for use
func getRepository(repositoryUrl string) (*git.Repository, error) {
	return git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL: repositoryUrl,
	})
}

// get the commit used for the component build
func getCommit(repositoryUrl, commitSha string) (*object.Commit, error) {
	repo, err := getRepository(repositoryUrl)
	if err != nil {
		return nil, err
	}

	commit, err := repo.CommitObject(plumbing.NewHash(commitSha))
	if err != nil {
		return nil, err
	}

	return commit, nil
}

// get the tag used for the component build
func getTag(repositoryUrl, tag string) (*plumbing.Reference, error) {
	repo, err := getRepository(repositoryUrl)
	if err != nil {
		return nil, err
	}

	ref, err := repo.Tag(tag)
	if err != nil {
		return nil, err
	}

	return ref, nil
}

// get the commit used for the build and return the repo url and the commit
func (c *commitSignoffSource) GetBuildSignOff() (*signOffSignature, error) {
	commit, err := getCommit(c.source, c.commitSha)
	if err != nil {
		return nil, err
	}

	return &signOffSignature{
		Payload: commit,
		Source:  c.source,
	}, nil
}

// get the tag used for the build and return the repo url and the commit
func (t *tagSignoffSource) GetBuildSignOff() (*signOffSignature, error) {
	ref, err := getTag(t.source, t.tag)
	if err != nil {
		return nil, err
	}

	return &signOffSignature{
		Payload: ref,
		Source:  t.source,
	}, nil
}

// get the jira used for sign off and return the jira and the jira url
func (j *jiraSignoffSource) GetBuildSignOff() (*signOffSignature, error) {
	return &signOffSignature{}, nil
}
