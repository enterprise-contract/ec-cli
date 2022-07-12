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

type commitSignOff struct {
	source    string
	commitSha string
}

type signOffSource interface {
	GetSignOff() (*signOffSignature, error)
	getSource() (interface{}, error)
}

type signOffSignature struct {
	Payload    interface{} `json:"payload"`
	Signatures string      `json:"signatures"`
}

// From an attestation, find the signOff source (commit, tag, jira)
func (a *attestation) NewSignoffSource() (signOffSource, error) {
	// the signoff source can be determined by looking into the attestation.
	// the attestation can have an env var or something that this can key off of

	commitSha := a.getBuildCommitSha()
	if commitSha != "" {
		return &commitSignOff{
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

// the git url used for the component build
func (a *attestation) getBuildTag() string {
	return a.Predicate.Invocation.Parameters["tag"]
}

func (c *commitSignOff) GetSignOff() (*signOffSignature, error) {
	commit, err := c.getSource()
	if err != nil {
		return nil, err
	}

	return &signOffSignature{
		Payload: commit.(*object.Commit),
	}, nil
}

func (c *commitSignOff) getSource() (interface{}, error) {
	repo, err := git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL: c.source,
	})
	if err != nil {
		return nil, err
	}

	commit, err := repo.CommitObject(plumbing.NewHash(c.commitSha))
	if err != nil {
		return nil, err
	}

	return commit, nil
}
