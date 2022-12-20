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

//go:build unit

package kubernetes

import (
	"context"
	"os"
	"path"
	"testing"

	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/fake"
)

var fakeClient dynamic.Interface

var testECP = ecc.EnterpriseContractPolicy{
	TypeMeta: v1.TypeMeta{
		Kind:       "EnterpriseContractPolicy",
		APIVersion: "appstudio.redhat.com/v1alpha1",
	},
	ObjectMeta: v1.ObjectMeta{
		Name:      "ec-policy",
		Namespace: "test",
	},
	Spec: ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{
			{
				Policy: []string{"test_policies"},
			},
		},
	},
}

var testKubeconfig = []byte(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://api.test
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    namespace: test
  name: test-context
current-context: test-context
`)

func init() {
	scheme := runtime.NewScheme()
	err := ecc.AddToScheme(scheme)
	if err != nil {
		panic(err)
	}

	fakeClient = fake.NewSimpleDynamicClient(scheme, &testECP)
}

func Test_FetchEnterpriseContractPolicy(t *testing.T) {
	testCases := []struct {
		name       string
		policyName string
		ecp        *ecc.EnterpriseContractPolicy
		err        string
	}{
		{
			name:       "fetch-with-name-and-namespace",
			policyName: "test/ec-policy",
			ecp:        &testECP,
		},
		{
			name:       "fetch-with-name-only",
			policyName: "ec-policy",
			ecp:        &testECP,
		},
		{
			name:       "fetch-policy-not-found",
			policyName: "missing/ec-policy",
			err:        `enterprisecontractpolicies.appstudio.redhat.com "ec-policy" not found`,
		},
	}

	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			k := kubernetesClient{
				client: fakeClient,
			}

			kubeconfigFile := path.Join(t.TempDir(), "KUBECONFIG")
			err := os.WriteFile(kubeconfigFile, testKubeconfig, 0777)
			assert.NoError(t, err)
			t.Setenv("KUBECONFIG", kubeconfigFile)

			got, err := k.FetchEnterpriseContractPolicy(context.TODO(), c.policyName)

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

func Test_FailureToCreateClient(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistant")
	_, err := createK8SClient()

	assert.EqualError(t, err, "invalid configuration: no configuration has been provided, try setting KUBERNETES_MASTER environment variable")
}
