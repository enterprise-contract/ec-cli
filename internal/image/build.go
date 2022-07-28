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
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/hacbs-contract/ec-cli/internal/kubernetes"
	ecp "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"
)

var kubernetesClientCreator = kubernetes.NewClient

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

type k8sSignOff struct {
	repo      string
	commitSha string
	getSource func(string, string) error
}

// there can be multiple sign off sources (git commit, tag and jira issues)
type signOffGetter interface {
	GetSignOff() (*signOffSignature, error)
}

type SignOffSource interface {
	GetSource() (signOffGetter, error)
}

// holds config information to get client instance
type K8sSource struct {
	namespace string
	server    string
	resource  string
}

// holds config information to get client instance
type GitSource struct {
	repoUrl   string
	commitSha string
}

type commit struct {
	RepoUrl string `json:"repoUrl"`
	Sha     string `json:"sha"`
	Author  string `json:"author"`
	Date    string `json:"date"`
	Message string `json:"message"`
}

type k8sResource struct {
	RepoUrl string `json:"repoUrl"`
	Sha     string `json:"sha"`
	Author  string `json:"author"`
}

type signOffSignature struct {
	RepoUrl    string   `json:"repoUrl"`
	Commit     string   `json:"commit"`
	Signatures []string `json:"signatures"`
}

// get the source (commit, k8sresource), return signOffGetter
// have the source implement GetSignOff

func (g *GitSource) GetSource() (signOffGetter, error) {
	repo, err := getRepository(g.repoUrl)
	if err != nil {
		return nil, err
	}
	gitCommit, err := getCommit(repo, g.commitSha)
	if err != nil {
		return nil, err
	}

	return &commit{
		RepoUrl: g.repoUrl,
		Sha:     gitCommit.Hash.String(),
		Author:  fmt.Sprintf("%s <%s>", gitCommit.Author.Name, gitCommit.Author.Email),
		Date:    gitCommit.Author.When.String(),
		Message: gitCommit.Message,
	}, nil
}

// fetch the k8s resource from the cluster
func (k *K8sSource) GetSource() (signOffGetter, error) {
	ecp, err := fetchECSource(k.resource)
	if err != nil {
		return nil, err
	}
	return &k8sResource{
		RepoUrl: "https://github.com/joejstuart/ec-cli.git",
		// Sha can be a branch. If that's the case, let the policy handle it
		Sha:    *ecp.Spec.Description,
		Author: "ec@redhat.com",
	}, nil
}

func (a *attestation) NewGitSource() (*GitSource, error) {
	repoUrl := a.getBuildSCM()
	sha := a.getBuildCommitSha()

	if repoUrl != "" && sha != "" {
		return &GitSource{
			repoUrl:   a.getBuildSCM(),
			commitSha: a.getBuildCommitSha(),
		}, nil
	}
	return nil, errors.New(
		fmt.Sprintf("there is no authorization source in attestation. sha: %v, url: %v", repoUrl, sha),
	)
}

func NewK8sSource(server, namespace, resource string) (*K8sSource, error) {
	return &K8sSource{
		namespace: namespace,
		server:    server,
		resource:  resource,
	}, nil
}

func fetchECSource(resource string) (*ecp.EnterpriseContractPolicy, error) {
	policyName, err := kubernetes.NamespacedName(resource)
	if err != nil {
		return nil, err
	}
	k8s, err := kubernetesClientCreator()
	if err != nil {
		log.Debug("Failed to initialize Kubernetes client")
		return nil, err
	}

	ecp, err := k8s.FetchEnterpriseContractPolicy(context.TODO(), *policyName)
	if err != nil {
		log.Debug("Failed to fetch the enterprise contract policy from the cluster!")
		return nil, err
	}
	return ecp, nil
}

// get the last commit used for the component build
func (a *attestation) getBuildCommitSha() string {
	sha := "6c1f093c0c197add71579d392da8a79a984fcd62"
	if len(a.Predicate.Materials) == 1 {
		sha = a.Predicate.Materials[0].Digest["sha1"]
	}
	log.Debugf("using commit with sha: '%v'", sha)
	return sha
}

// the git url used for the component build
func (a *attestation) getBuildSCM() string {
	uri := "https://github.com/joejstuart/ec-cli.git"
	if len(a.Predicate.Materials) == 1 {
		uri = a.Predicate.Materials[0].Uri
	}
	log.Debugf("using repo '%v'", uri)
	return uri
}

// returns the signOff signature and body of the source
func (c *commit) GetSignOff() (*signOffSignature, error) {
	return &signOffSignature{
		RepoUrl:    c.RepoUrl,
		Commit:     c.Sha,
		Signatures: captureCommitSignOff(c.Message),
	}, nil
}

func (k *k8sResource) GetSignOff() (*signOffSignature, error) {
	// fetch the k8s resource
	return &signOffSignature{
		RepoUrl: k.RepoUrl,
		Commit:  k.Sha,
		Signatures: []string{
			k.Author,
		},
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

func getECResource(namespace, server string) error {
	return nil
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

func GetAuthorization(source SignOffSource) (*signOffSignature, error) {
	authorizationSource, err := source.GetSource()
	if err != nil {
		return nil, err
	}

	return authorizationSource.GetSignOff()
}

func PrintAuthorization(authorization *signOffSignature, att *attestation) error {
	authPayload, err := json.Marshal(authorization)
	if err != nil {
		return err
	}
	fmt.Println(string(authPayload))

	attPayload, err := json.Marshal(att)
	if err != nil {
		return err
	}
	fmt.Println(attPayload)

	return nil
}
