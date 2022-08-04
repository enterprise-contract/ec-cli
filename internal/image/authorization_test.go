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
	"testing"

	ecp "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func mockFetchECSource(resource string) (*ecp.EnterpriseContractPolicy, error) {
	description := "very descriptive"
	return &ecp.EnterpriseContractPolicy{
		Spec: ecp.EnterpriseContractPolicySpec{
			Description: &description,
		},
	}, nil
}

func Test_NewK8sSource(t *testing.T) {
	wanted := &K8sSource{
		namespace:   "enterprise-contract",
		server:      "k8s-server",
		resource:    "ecp/resource",
		fetchSource: mockFetchECSource,
	}

	source, err := NewK8sSource("k8s-server", "enterprise-contract", "ecp/resource")
	assert.ObjectsAreEqualValues(wanted, source)
	assert.NoError(t, err)
}

func Test_GeKk8sSignOff(t *testing.T) {
	input := &k8sResource{
		RepoUrl: "my-git-repo",
		Sha:     "1234",
		Author:  "ec@redhat.com",
	}
	expected := &authorizationSignature{
		RepoUrl:     "my-git-repo",
		Commit:      "1234",
		Authorizers: []string{"ec@redhat.com"},
	}

	signOff, err := input.GetSignOff()
	assert.NoError(t, err)
	assert.Equal(t, expected, signOff)
}

func Test_GetGitSignOff(t *testing.T) {
	input := &commit{
		RepoUrl: "my-git-repo",
		Sha:     "1234",
		Author:  "ec@redhat.com",
		Date:    "01-01-2022",
		Message: "Signed-off-by: ec <ec@redhat.com>",
	}
	expected := &authorizationSignature{
		RepoUrl:     "my-git-repo",
		Commit:      "1234",
		Authorizers: []string{"ec@redhat.com"},
	}

	signOff, err := input.GetSignOff()
	assert.NoError(t, err)
	assert.Equal(t, expected, signOff)
}

func Test_GetAuthorization(t *testing.T) {
	tests := []struct {
		input AuthorizationSource
		want  *authorizationSignature
		err   error
	}{
		{
			&K8sSource{
				namespace:   "enterprise-contract",
				server:      "k8s-server",
				resource:    "ecp/resource",
				fetchSource: mockFetchECSource,
			},
			&authorizationSignature{
				RepoUrl:     "my-git-repo",
				Commit:      "1234",
				Authorizers: []string{"ec@redhat.com"},
			},
			nil,
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("GetAuthorization=%d", i), func(t *testing.T) {
			signOff, err := GetAuthorization(tc.input)
			assert.ObjectsAreEqualValues(tc.want, signOff)
			assert.Equal(t, tc.err, err)
		})
	}
}
