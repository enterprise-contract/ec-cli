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
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"

	ecp "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/hashicorp/go-getter"
	"github.com/stretchr/testify/assert"
)

func sourceFetchStub(dst string, src string, opts ...getter.ClientOption) error {
	err := os.MkdirAll(dst, 0755)
	if err != nil {
		return err
	}
	f, err := os.Create(path.Join(dst, "input.json"))
	if err != nil {
		return err
	}
	fmt.Fprint(f, src)
	f.Close()

	return nil
}

func Test_fetchPolicySources(t *testing.T) {
	rev1 := "revision1"
	rev2 := "revision2"

	s := policySource{
		fetch: sourceFetchStub,
	}

	sources, err := s.fetchPolicySources(context.TODO(), ecp.EnterpriseContractPolicySpec{
		Sources: []ecp.PolicySource{
			{
				GitRepository: &ecp.GitPolicySource{
					Repository: "repository1",
					Revision:   &rev1,
				},
			},
			{
				GitRepository: &ecp.GitPolicySource{
					Repository: "repository2",
					Revision:   &rev2,
				},
			},
		},
	})
	defer func() {
		for _, d := range sources {
			os.RemoveAll(d)
		}
	}()

	assert.NoError(t, err)
	assert.Len(t, sources, 2, "expected two policy source directories")

	input1 := path.Join(sources[0], "input.json")
	assert.FileExists(t, input1)
	content1, err := ioutil.ReadFile(input1)
	assert.NoError(t, err)
	assert.Equal(t, "repository1?ref=revision1", string(content1))

	input2 := path.Join(sources[1], "input.json")
	assert.FileExists(t, input2)
	content2, err := ioutil.ReadFile(input2)
	assert.NoError(t, err)
	assert.Equal(t, "repository2?ref=revision2", string(content2))
}
