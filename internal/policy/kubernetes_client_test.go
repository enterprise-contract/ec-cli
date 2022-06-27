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
	"os"
	"path"
	"testing"

	ecp "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var fakeClient client.Client

func init() {
	scheme := runtime.NewScheme()
	err := ecp.AddToScheme(scheme)
	if err != nil {
		panic(err)
	}

	fakeClient = fake.NewClientBuilder().WithScheme(scheme).WithObjects(&testECP).Build()
}

const testKubeconfig = `
apiVersion: v1
kind: Config
contexts:
- context:
    namespace: test
  name: test/my-cluster-com:6443/kube:admin
current-context: test/my-cluster-com:6443/kube:admin
`

func Test_FetchEnterpriseContractPolicy(t *testing.T) {
	testCases := []struct {
		name           string
		namespacedName types.NamespacedName
		ecp            *ecp.EnterpriseContractPolicy
		kubeconfig     string
		err            string
	}{
		{
			name:           "fetch-with-name-and-namespace",
			namespacedName: types.NamespacedName{Name: "ec-policy", Namespace: "test"},
			ecp:            &testECP,
			kubeconfig:     "",
			err:            "",
		},
		{
			name:           "fetch-with-name-only",
			namespacedName: types.NamespacedName{Name: "ec-policy"},
			ecp:            &testECP,
			kubeconfig:     testKubeconfig,
			err:            "",
		},
		{
			name:           "fetch-with-undetectable-namespace",
			namespacedName: types.NamespacedName{Name: "ec-policy"},
			ecp:            nil,
			kubeconfig:     "",
			err:            "Unable to determine current namespace: missing current context",
		},
		{
			name:           "fetch-policy-not-found",
			namespacedName: types.NamespacedName{Name: "ec-policy", Namespace: "missing"},
			ecp:            nil,
			kubeconfig:     "",
			err:            `enterprisecontractpolicies.appstudio.redhat.com "ec-policy" not found`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.kubeconfig != "" {
				kubeconfig := path.Join(t.TempDir(), "KUBECONFIG")
				kubeconfigFile, err := os.Create(kubeconfig)
				assert.NoError(t, err)
				defer kubeconfigFile.Close()
				_, err = kubeconfigFile.WriteString(tc.kubeconfig)
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv("KUBECONFIG", kubeconfig)
			}
			k := kubernetes{
				client: fakeClient,
			}

			got, err := k.fetchEnterpriseContractPolicy(context.TODO(), tc.namespacedName)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}

			if tc.ecp == nil {
				assert.Nil(t, got)
			} else {
				assert.Equal(t, *tc.ecp, *got, "should return the stubbed EnterpriseContractPolicy")
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
