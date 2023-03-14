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
	"context"
	"fmt"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/in-toto/in-toto-golang/in_toto"
	log "github.com/sirupsen/logrus"

	"github.com/hacbs-contract/ec-cli/internal/attestation"
)

func NewGitSource(att attestation.Attestation[in_toto.ProvenanceStatementSLSA02]) (*GitSource, error) {
	statement := att.Statement()
	repoUrl := getBuildSCM(statement)
	sha := getBuildCommitSha(statement)

	if repoUrl != "" && sha != "" {
		return &GitSource{
			repoUrl:     repoUrl,
			commitSha:   sha,
			fetchSource: fetchCommitSource,
		}, nil
	}
	return nil, fmt.Errorf(
		"there is no authorization source in attestation. sha: %v, url: %v", repoUrl, sha,
	)
}

// get the last commit used for the component build
func getBuildCommitSha(statement in_toto.ProvenanceStatementSLSA02) string {
	sha := "" //6c1f093c0c197add71579d392da8a79a984fcd62"
	if len(statement.Predicate.Materials) == 1 {
		sha = statement.Predicate.Materials[0].Digest["sha1"]
	}
	log.Debugf("using commit with sha: '%v'", sha)
	return sha
}

// the git url used for the component build
func getBuildSCM(statement in_toto.ProvenanceStatementSLSA02) string {
	uri := "" //https://github.com/joejstuart/ec-cli.git"
	if len(statement.Predicate.Materials) == 1 {
		// If our URI has 'git+https' as the scheme, we will strip the "git+" portion.
		uri = strings.TrimPrefix(statement.Predicate.Materials[0].URI, "git+")
	}
	log.Debugf("using repo '%v'", uri)
	return uri
}

func fetchCommitSource(ctx context.Context, repoUrl, commitSha string) (*object.Commit, error) {
	repo, err := getRepository(repoUrl)
	if err != nil {
		return nil, err
	}
	return getCommit(repo, commitSha)
}
