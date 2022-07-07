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

package policy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"testing"

	ecp "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/hashicorp/go-getter"
	"github.com/open-policy-agent/conftest/output"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var testECP ecp.EnterpriseContractPolicy = ecp.EnterpriseContractPolicy{
	TypeMeta: v1.TypeMeta{
		Kind:       "EnterpriseContractPolicy",
		APIVersion: "appstudio.redhat.com/v1alpha1",
	},
	ObjectMeta: v1.ObjectMeta{
		Name:      "ec-policy",
		Namespace: "test",
	},
	Spec: ecp.EnterpriseContractPolicySpec{
		Sources: []ecp.PolicySource{
			{
				GitRepository: &ecp.GitPolicySource{
					Repository: "test_policies",
				},
			},
		},
	},
}

func init() {
	kubernetesCreator = func() (*kubernetes, error) {
		return &kubernetes{
			client: fakeClient,
		}, nil
	}
}

func Test_NewPolicyEvaluator(t *testing.T) {
	cases := []struct {
		name         string
		policy       string
		expectedName *types.NamespacedName
		err          error
	}{
		{
			name:         "empty",
			policy:       "",
			expectedName: nil,
			err:          errors.New("policy: policy name is required"),
		},
		{
			name:   "without namespace",
			policy: "policy",
			expectedName: &types.NamespacedName{
				Name: "policy",
			},
			err: nil,
		},
		{
			name:   "with namespace",
			policy: "namespace/policy",
			expectedName: &types.NamespacedName{
				Name:      "policy",
				Namespace: "namespace",
			},
			err: nil,
		},
	}

	for _, c := range cases {
		created, err := NewPolicyEvaluator(c.policy)
		assert.Equal(t, c.err, err, c.name)
		if created == nil {
			assert.Nil(t, c.expectedName, "PolicyEvaluator wasn't created but an expectedName was set")
		} else {
			assert.Equal(t, *c.expectedName, created.(*policyEvaluator).policyName, c.name)
		}
	}
}

func policyFetchStub(dst string, src string, opts ...getter.ClientOption) error {
	err := os.MkdirAll(dst, 0755)
	if err != nil {
		return err
	}
	f, err := os.Create(path.Join(dst, "main.rego"))
	if err != nil {
		return err
	}
	fmt.Fprint(f, `package main`)
	f.Close()

	return nil
}

func Test_Evaluate(t *testing.T) {
	evaluator := policyEvaluator{
		policyName: types.NamespacedName{
			Name:      "ec-policy",
			Namespace: "test",
		},
		k8s: kubernetes{
			client: fakeClient,
		},
		source: policySource{
			fetch: policyFetchStub,
		},
	}

	attestations, err := testAttestations()
	assert.NoError(t, err)

	results, err := evaluator.Evaluate(context.TODO(), attestations)
	assert.NoError(t, err)
	assert.Len(t, results, 1, "expected one result")

	result := results[0]
	assert.Equal(t, releaseNamespace, result.Namespace)
	assert.Zero(t, result.Successes)
	assert.Empty(t, result.Skipped)
	assert.Empty(t, result.Warnings)
	assert.Empty(t, result.Failures)
	assert.Empty(t, result.Exceptions)
	assert.Empty(t, result.Queries)
}

func Test_EmptyAttestations(t *testing.T) {
	evaluator := policyEvaluator{}

	attestations := []oci.Signature{}

	results, err := evaluator.Evaluate(context.TODO(), attestations)
	assert.NoError(t, err)
	assert.Len(t, results, 1, "expected one result")

	result := results[0]
	assert.Empty(t, result.Namespace)
	assert.Zero(t, result.Successes)
	assert.Empty(t, result.Skipped)
	assert.Empty(t, result.Warnings)
	assert.Equal(t, []output.Result{
		{
			Message: "no attestations available",
		},
	}, result.Failures)
	assert.Empty(t, result.Exceptions)
	assert.Empty(t, result.Queries)
}
