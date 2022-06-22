/*
Copyright © 2022 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package policy

import (
	"context"
	"errors"
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

func Test_FetchEnterpriseContractPolicy(t *testing.T) {
	k := kubernetes{
		client: fakeClient,
	}

	got, err := k.fetchEnterpriseContractPolicy(context.TODO(), types.NamespacedName{
		Name:      "ec-policy",
		Namespace: "test",
	})

	assert.NoError(t, err)
	assert.Equal(t, testECP, *got, "should return the stubbed EnterpriseContractPolicy")
}

func Test_FetchEnterpriseContractPolicyNotFound(t *testing.T) {
	k := kubernetes{
		client: fakeClient,
	}

	got, err := k.fetchEnterpriseContractPolicy(context.TODO(), types.NamespacedName{
		Name:      "missing",
		Namespace: "test",
	})

	expected := errors.New("can't fetch EnterpriseContractPolicy `missing` in namespace `test")
	assert.ErrorAs(t, err, &expected)
	assert.Nil(t, got)
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
