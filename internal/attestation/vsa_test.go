// Copyright The Enterprise Contract Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"context"
	"testing"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/stretchr/testify/assert"

	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
)

type mockPolicy struct {
	ecc.EnterpriseContractPolicySpec
	// choosenTime   string
	// effectiveTime *time.Time
}

func (m mockPolicy) PublicKeyPEM() ([]byte, error) {
	return []byte{}, nil
}

func (m mockPolicy) CheckOpts() (*cosign.CheckOpts, error) {
	return nil, nil
}

func (m mockPolicy) WithSpec(spec ecc.EnterpriseContractPolicySpec) policy.Policy {
	return m
}

func (m mockPolicy) Spec() ecc.EnterpriseContractPolicySpec {
	return m.EnterpriseContractPolicySpec
}

func (m mockPolicy) EffectiveTime() time.Time {
	return time.Now()
}

func (m mockPolicy) AttestationTime(time.Time) {

}

func (m mockPolicy) Identity() cosign.Identity {
	return cosign.Identity{}
}

func (m mockPolicy) Keyless() bool {
	return true
}

type mockPolicyUrl struct {
	Url string
}

func (m *mockPolicyUrl) GetPolicy(ctx context.Context, workDir string, showMsg bool) (string, error) {
	return "", nil
}

func (m *mockPolicyUrl) PolicyUrl() string {
	return m.Url
}

func (m *mockPolicyUrl) Subdir() string {
	return ""
}

func TestVsaFromImageValidation(t *testing.T) {
	verifiedTime := time.Now().String()
	cases := []struct {
		name         string
		time         string
		results      []evaluator.Outcome
		policies     []source.PolicySource
		policy       policy.Policy
		attestations []Attestation
		expected     ProvenanceStatementVSA
	}{
		{
			name: "verified success - vsa provenance",
			time: verifiedTime,
			results: []evaluator.Outcome{
				{
					Successes: []evaluator.Result{
						{
							Message:  "Success",
							Metadata: map[string]interface{}{"code": "test.rule"},
						},
					},
				},
			},
			policies: []source.PolicySource{&mockPolicyUrl{Url: "https://example.com"}},
			policy: mockPolicy{
				ecc.EnterpriseContractPolicySpec{
					Sources: []ecc.Source{
						{
							Config: &ecc.SourceConfig{
								Include: []string{"@redhat"},
							},
						},
					},
				},
			},
			attestations: []Attestation{slsaProvenance{}},
			expected: ProvenanceStatementVSA{
				StatementHeader: in_toto.StatementHeader{
					Type:          StatmentVSA,
					PredicateType: PredicateVSAProvenance,
				},
				Predicate: predicate{
					Verifier: map[string]string{
						"id": "ec",
					},
					VerificationResult: "Success",
					TimeVerified:       verifiedTime,
					InputAttestations: []attestationSource{
						{version: "https://slsa.dev/provenance/v0.2"},
					},
					Policies: []policySource{
						{uri: "https://example.com"},
					},
					VerifiedRules:       []string{"test.rule"},
					VerifiedCollections: []string{"redhat"},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := VsaFromImageValidation(c.time, c.results, c.policies, c.policy, c.attestations)
			assert.Equal(t, c.expected, got)
		})
	}
}
