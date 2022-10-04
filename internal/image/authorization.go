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
	"fmt"
	"net/mail"
	"os"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"

	"github.com/hacbs-contract/ec-cli/internal/kubernetes"
	"github.com/hacbs-contract/ec-cli/internal/policy"
)

var kubernetesClientCreator = kubernetes.NewClient

// there can be multiple sign off sources (git commit, tag and jira issues)
type authorizationGetter interface {
	GetSignOff() ([]authorizationSignature, error)
}

type AuthorizationSource interface {
	GetSource(context.Context) (authorizationGetter, error)
}

// holds config information to get client instance
type K8sSource struct {
	policyConfiguration string
	fetchSource         func(context.Context, string) (*ecc.EnterpriseContractPolicySpec, error)
}

// holds config information to get client instance
type GitSource struct {
	repoUrl     string
	commitSha   string
	fetchSource func(context.Context, string, string) (*object.Commit, error)
}

// the object GitSource fetches
type commit struct {
	RepoUrl string `json:"repoUrl"`
	Sha     string `json:"sha"`
	Author  string `json:"author"`
	Date    string `json:"date"`
	Message string `json:"message"`
}

// the object K8sSource fetches
type k8sResource struct {
	Components []ecc.AuthorizedComponent
}

type authorizationSignature struct {
	RepoUrl     string   `json:"repoUrl"`
	Commit      string   `json:"commit"`
	Authorizers []string `json:"authorizers"`
}

func NewK8sSource(policyConfiguration string) (*K8sSource, error) {
	return &K8sSource{
		policyConfiguration: policyConfiguration,
		fetchSource:         fetchECSource,
	}, nil
}

func (g *GitSource) GetSource(ctx context.Context) (authorizationGetter, error) {
	gitCommit, err := g.fetchSource(ctx, g.repoUrl, g.commitSha)
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
func (k *K8sSource) GetSource(ctx context.Context) (authorizationGetter, error) {
	ecp, err := k.fetchSource(ctx, k.policyConfiguration)
	if err != nil {
		return nil, err
	}

	return &k8sResource{
		Components: ecp.Authorization.Components,
	}, nil
}

func GetK8sResource(ecp *ecc.EnterpriseContractPolicySpec) (authorizationGetter, error) {
	return &k8sResource{
		Components: ecp.Authorization.Components,
	}, nil
}

func fetchECSource(ctx context.Context, policyConfiguration string) (*ecc.EnterpriseContractPolicySpec, error) {
	ecp, err := policy.NewPolicy(ctx, policyConfiguration, "", "")
	if err != nil {
		log.Debug("Failed to fetch the enterprise contract policy from the cluster!")
		return nil, err
	}
	return ecp, nil
}

// returns the signOff signature and body of the source
func (c *commit) GetSignOff() ([]authorizationSignature, error) {
	return []authorizationSignature{
		{
			RepoUrl:     c.RepoUrl,
			Commit:      c.Sha,
			Authorizers: captureCommitSignOff(c.Message),
		},
	}, nil
}

func (k *k8sResource) GetSignOff() ([]authorizationSignature, error) {
	var k8sAuths []authorizationSignature
	for _, cmp := range k.Components {
		k8sAuths = append(k8sAuths,
			authorizationSignature{
				RepoUrl: cmp.Repository,
				Commit:  cmp.ChangeID,
				Authorizers: []string{
					cmp.Authorizer,
				},
			},
		)
	}
	return k8sAuths, nil
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

func GetAuthorization(ctx context.Context, source AuthorizationSource) ([]authorizationSignature, error) {
	authorizationSource, err := source.GetSource(ctx)
	if err != nil {
		return nil, err
	}

	return authorizationSource.GetSignOff()
}

func PrintAuthorization(authorization []authorizationSignature) error {
	authPayload, err := json.Marshal(authorization)
	if err != nil {
		return err
	}
	fmt.Println(string(authPayload))

	return nil
}
