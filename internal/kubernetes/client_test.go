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

package kubernetes

import (
	"context"
	"errors"
	"testing"

	ecp "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var fakeClient client.Client

var testECP = ecp.EnterpriseContractPolicy{
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
	scheme := runtime.NewScheme()
	err := ecp.AddToScheme(scheme)
	if err != nil {
		panic(err)
	}

	fakeClient = fake.NewClientBuilder().WithScheme(scheme).WithObjects(&testECP).Build()
}

func Test_FetchEnterpriseContractPolicy(t *testing.T) {
	testCases := []struct {
		name           string
		namespacedName types.NamespacedName
		ecp            *ecp.EnterpriseContractPolicy
		err            string
	}{
		{
			name:           "fetch-with-name-and-namespace",
			namespacedName: types.NamespacedName{Name: "ec-policy", Namespace: "test"},
			ecp:            &testECP,
		},
		{
			name:           "fetch-with-name-only",
			namespacedName: types.NamespacedName{Name: "ec-policy"},
			err:            "missing namespace",
		},
		{
			name:           "fetch-policy-not-found",
			namespacedName: types.NamespacedName{Name: "ec-policy", Namespace: "missing"},
			err:            `enterprisecontractpolicies.appstudio.redhat.com "ec-policy" not found`,
		},
	}

	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			k := Client{
				client: fakeClient,
			}

			got, err := k.FetchEnterpriseContractPolicy(context.TODO(), c.namespacedName)

			if c.err == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, c.err)
			}

			if c.ecp == nil {
				assert.Nil(t, got)
			} else {
				assert.Equal(t, *c.ecp, *got, "should return the stubbed EnterpriseContractPolicy")
			}
		})
	}
}

func Test_FailureToAddScheme(t *testing.T) {
	expected := errors.New("expected")

	def := ecp.AddToScheme
	ecp.AddToScheme = func(s *runtime.Scheme) error {
		return expected
	}
	defer func() {
		ecp.AddToScheme = def
	}()

	_, err := createControllerRuntimeClient()

	assert.EqualError(t, err, "expected")
}
