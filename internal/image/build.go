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
	"net/mail"
	"os"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
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

type commitSignOff struct {
	source        string
	commitSha     string
	getCommit     func(*git.Repository, string) (*object.Commit, error)
	getRepository func(string) (*git.Repository, error)
}

// there can be multiple sign off sources (git commit, tag and jira issues)
type signOffSource interface {
	GetSignOff() (*signOffSignature, error)
}

type commit struct {
	Sha     string `json:"sha"`
	Author  string `json:"author"`
	Date    string `json:"date"`
	Message string `json:"message"`
}

type signOffSignature struct {
	Body       interface{} `json:"body"`
	Signatures []string    `json:"signatures"`
}

// From an attestation, find the signOff source (commit, tag, jira)
func (a *attestation) NewSignOffSource() (signOffSource, error) {
	// the signoff source can be determined by looking into the attestation.
	// the attestation can have an env var or something that this can key off of

	commitSha := a.getBuildCommitSha()
	repo := a.getBuildSCM()
	if commitSha != "" && repo != "" {
		return &commitSignOff{
			source:        a.getBuildSCM(),
			commitSha:     commitSha,
			getCommit:     getCommit,
			getRepository: getRepository,
		}, nil
	}
	return nil, nil
}

// get the last commit used for the component build
func (a *attestation) getBuildCommitSha() string {
	sha := ""
	if len(a.Predicate.Materials) == 1 {
		sha = a.Predicate.Materials[0].Digest["sha1"]
	}
	log.Debugf("using commit with sha: '%v'", sha)
	return sha
}

// the git url used for the component build
func (a *attestation) getBuildSCM() string {
	uri := ""
	if len(a.Predicate.Materials) == 1 {
		uri = a.Predicate.Materials[0].Uri
	}
	log.Debugf("using repo '%v'", uri)
	return uri
}

// returns the signOff signature and body of the source
func (c *commitSignOff) GetSignOff() (*signOffSignature, error) {
	commit, err := getCommitSource(c)
	if err != nil {
		return nil, err
	}

	return &signOffSignature{
		Body:       commit,
		Signatures: captureCommitSignOff(commit.Message),
	}, nil
}

func getRepository(url string) (*git.Repository, error) {
	dir, err := os.MkdirTemp("", "ec_commit")
	if err != nil {
		return nil, err
	}

	return git.PlainClone(dir, false, &git.CloneOptions{URL: url})
}

func getCommit(repository *git.Repository, sha string) (*object.Commit, error) {
	return repository.CommitObject(plumbing.NewHash(sha))
}

// get the build commit source for use in GetSignOff
func getCommitSource(c *commitSignOff) (*commit, error) {
	repo, err := c.getRepository(c.source)
	if err != nil {
		return nil, err
	}

	gitCommit, err := c.getCommit(repo, c.commitSha)
	if err != nil {
		return nil, err
	}

	return &commit{
		Sha:     gitCommit.Hash.String(),
		Author:  fmt.Sprintf("%s <%s>", gitCommit.Author.Name, gitCommit.Author.Email),
		Date:    gitCommit.Author.When.String(),
		Message: gitCommit.Message,
	}, nil

}

// parse a commit and capture signatures
func captureCommitSignOff(message string) []string {
	var capturedSignatures []string
	signatureHeader := "Signed-off-by:"
	// loop over each line of the commit message looking for "Signed-off-by:"
	for _, line := range strings.Split(message, "\n") {
		regex := fmt.Sprintf("^%s", signatureHeader)
		match, _ := regexp.MatchString(regex, line)
		// if there's a match, split on "Signed-off-by:", then capture each signature after
		if match {
			results := strings.Split(line, signatureHeader)
			signatures, err := mail.ParseAddressList(results[len(results)-1])
			if err != nil {
				continue
			}
			for _, signature := range signatures {
				capturedSignatures = append(capturedSignatures, signature.Address)
			}
		}
	}

	return capturedSignatures
}
