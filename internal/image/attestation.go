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
	"fmt"

	"github.com/go-git/go-git/v5/plumbing/object"
	log "github.com/sirupsen/logrus"
)

type invocation struct {
	ConfigSource map[string]interface{} `json:"configSource"`
	Parameters   map[string]string      `json:"parameters"`
	Environment  map[string]interface{} `json:"environment"`
}

type materials struct {
	Uri    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

type predicate struct {
	Invocation  invocation             `json:"invocation"`
	BuildType   string                 `json:"buildType"`
	Metadata    map[string]interface{} `json:"metadata"`
	Builder     map[string]interface{} `json:"builder"`
	BuildConfig map[string]interface{} `json:"buildConfig"`
	Materials   []materials            `json:"materials"`
}

type attestation struct {
	Predicate     predicate                `json:"predicate"`
	PredicateType string                   `json:"predicateType"`
	Subject       []map[string]interface{} `json:"subject"`
	Type          string                   `json:"_type"`
}

func (a *attestation) NewGitSource() (*GitSource, error) {
	repoUrl := a.getBuildSCM()
	sha := a.getBuildCommitSha()

	if repoUrl != "" && sha != "" {
		return &GitSource{
			repoUrl:     a.getBuildSCM(),
			commitSha:   a.getBuildCommitSha(),
			fetchSource: fetchCommitSource,
		}, nil
	}
	return nil, fmt.Errorf(
		"there is no authorization source in attestation. sha: %v, url: %v", repoUrl, sha,
	)
}

// get the last commit used for the component build
func (a *attestation) getBuildCommitSha() string {
	sha := "" //6c1f093c0c197add71579d392da8a79a984fcd62"
	if len(a.Predicate.Materials) == 1 {
		sha = a.Predicate.Materials[0].Digest["sha1"]
	}
	log.Debugf("using commit with sha: '%v'", sha)
	return sha
}

// the git url used for the component build
func (a *attestation) getBuildSCM() string {
	uri := "" //https://github.com/joejstuart/ec-cli.git"
	if len(a.Predicate.Materials) == 1 {
		uri = a.Predicate.Materials[0].Uri
	}
	log.Debugf("using repo '%v'", uri)
	return uri
}

func fetchCommitSource(repoUrl, commitSha string) (*object.Commit, error) {
	repo, err := getRepository(repoUrl)
	if err != nil {
		return nil, err
	}
	return getCommit(repo, commitSha)
}
