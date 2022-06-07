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
	"os"

	ecp "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/hashicorp/go-getter"
)

type fetcherFn func(string, string, ...getter.ClientOption) error

type policySource struct {
	fetch fetcherFn
}

// NewPolicySource constructs the default policySource
func NewPolicySource() policySource {
	return policySource{
		fetch: getter.Get,
	}
}

func (s *policySource) fetchPolicySources(ctx context.Context, spec ecp.EnterpriseContractPolicySpec) ([]string, error) {
	policySources := make([]string, 0, len(spec.Sources))

	for _, source := range spec.Sources {
		if source.GitRepository != nil {
			git := *source.GitRepository
			s, err := s.fetchPolicySourceFromGit(ctx, git.Repository, git.Revision)
			if err != nil {
				return nil, err
			}

			policySources = append(policySources, *s)
		}
	}

	return policySources, nil
}

func (s *policySource) fetchPolicySourceFromGit(ctx context.Context, repository string, revision *string) (*string, error) {
	source := repository
	if revision != nil {
		source += "?ref=" + *revision
	}

	dest, err := os.MkdirTemp("", "ecp_source.*")
	if err != nil {
		return nil, err
	}

	if err := s.fetch(dest, source, getter.WithContext(ctx)); err != nil {
		return nil, err
	}

	return &dest, nil
}
