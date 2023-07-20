// Copyright The Enterprise Contract Contributors
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

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	log "github.com/sirupsen/logrus"

	"github.com/enterprise-contract/ec-cli/internal/policy"
)

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
	fetchSource         func(context.Context, string) (policy.Policy, error)
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

// fetch the k8s resource from the cluster
func (k *K8sSource) GetSource(ctx context.Context) (authorizationGetter, error) {
	ecp, err := k.fetchSource(ctx, k.policyConfiguration)
	if err != nil {
		return nil, err
	}

	return &k8sResource{
		Components: ecp.Spec().Authorization.Components,
	}, nil
}

func GetK8sResource(ecp *ecc.EnterpriseContractPolicySpec) (authorizationGetter, error) {
	return &k8sResource{
		Components: ecp.Authorization.Components,
	}, nil
}

func fetchECSource(ctx context.Context, policyConfiguration string) (policy.Policy, error) {
	p, err := policy.NewPolicy(ctx, policyConfiguration, "", "", "", cosign.Identity{})
	if err != nil {
		log.Debug("Failed to fetch the enterprise contract policy from the cluster!")
		return nil, err
	}
	return p, nil
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
