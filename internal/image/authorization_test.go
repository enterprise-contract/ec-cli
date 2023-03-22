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

package image

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/policy"
)

func mockFetchECSource(ctx context.Context, resource string) (p policy.Policy, err error) {
	spec := ecc.EnterpriseContractPolicySpec{
		Description: "very descriptive",
		Authorization: &ecc.Authorization{
			Components: []ecc.AuthorizedComponent{
				{
					ChangeID:   "1234",
					Repository: "my-git-repo",
					Authorizer: "ec@redhat.com",
				},
			},
		},
	}

	p, err = policy.NewOfflinePolicy(ctx, policy.Now)
	if err != nil {
		return
	}

	return p.WithSpec(spec), nil
}

func mockPolicyConfigurationString() string {
	config := &ecc.EnterpriseContractPolicySpec{
		Description: "very descriptive",
	}
	configJson, _ := json.Marshal(config)
	return string(configJson)
}

func Test_NewK8sSource(t *testing.T) {
	source, err := NewK8sSource(mockPolicyConfigurationString())
	assert.IsType(t, &K8sSource{}, source)
	assert.NoError(t, err)
}

func Test_GeKk8sSignOff(t *testing.T) {
	input := &k8sResource{
		Components: []ecc.AuthorizedComponent{
			{
				ChangeID:   "1234",
				Repository: "my-git-repo",
				Authorizer: "ec@redhat.com",
			},
		},
	}
	expected := []authorizationSignature{
		{
			RepoUrl:     "my-git-repo",
			Commit:      "1234",
			Authorizers: []string{"ec@redhat.com"},
		},
	}

	signOff, err := input.GetSignOff()
	assert.NoError(t, err)
	assert.Equal(t, expected, signOff)
}

func Test_GetAuthorization(t *testing.T) {
	tests := []struct {
		input AuthorizationSource
		want  []authorizationSignature
		err   error
	}{
		{
			&K8sSource{
				policyConfiguration: mockPolicyConfigurationString(),
				fetchSource:         mockFetchECSource,
			},
			[]authorizationSignature{
				{
					RepoUrl:     "my-git-repo",
					Commit:      "1234",
					Authorizers: []string{"ec@redhat.com"},
				},
			},
			nil,
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("GetAuthorization=%d", i), func(t *testing.T) {
			signOff, err := GetAuthorization(context.Background(), tc.input)
			assert.Equal(t, tc.want, signOff)
			assert.Equal(t, tc.err, err)
		})
	}
}
