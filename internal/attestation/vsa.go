// Copyright The Enterprise Contract Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"strings"
	"time"

	"github.com/in-toto/in-toto-golang/in_toto"

	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
)

const (
	// Make it visible elsewhere
	PredicateVSAProvenance = "https://slsa.dev/verification_summary/v1"
	StatmentVSA            = "https://in-toto.io/Statement/v1"
)

type ProvenanceStatementVSA struct {
	in_toto.StatementHeader
	Predicate predicate `json:"predicate"`
}

type policySource struct {
	uri string
}

type attestationSource struct {
	digest map[string]string
}

type predicate struct {
	Verifier            map[string]string   `json:"verifier"`
	TimeVerified        string              `json:"timeVerified"`
	ResourceUri         string              `json:"resourceUri"`
	Policies            []policySource      `json:"policies"`
	InputAttestations   []attestationSource `json:"intputAttestations"`
	VerificationResult  string              `json:"verificationResult"`
	VerifiedRules       []string            `json:"verifiedRules"`
	VerifiedCollections []string            `json:"verfiedCollection"`
	SlsaVersion         string              `json:"slsaVersion"`
}

func VsaFromImageValidation(results []evaluator.Outcome, policies []source.PolicySource, policy policy.Policy, attestations []Attestation) (ProvenanceStatementVSA, error) {
	var verifiedPolicies []policySource
	for _, p := range policies {
		verifiedPolicies = append(verifiedPolicies, policySource{uri: p.PolicyUrl()})
	}

	var verfiedResults int
	var verifiedLevels []string
	for _, res := range results {
		for _, success := range res.Successes {
			verifiedLevels = append(verifiedLevels, success.Metadata["code"].(string))
		}
		verfiedResults = verfiedResults + len(res.Failures)
	}
	verificationResult := "Success"
	if verfiedResults > 0 {
		verificationResult = "Failure"
	}

	var verifiedCollections []string
	for _, source := range policy.Spec().Sources {
		for _, include := range source.Config.Include {
			splitInclude := strings.Split(include, "@")
			if len(splitInclude) > 1 {
				verifiedCollections = append(verifiedCollections, splitInclude[1])
			}
		}
	}

	var slsaVersion string
	var digest map[string]string
	var subject []in_toto.Subject
	for _, sp := range attestations {
		slsaVersion = sp.PredicateType()
		digest = sp.Digest()
		subject = sp.Subject()
	}

	return ProvenanceStatementVSA{
		StatementHeader: in_toto.StatementHeader{
			Type:          StatmentVSA,
			PredicateType: PredicateVSAProvenance,
			Subject:       subject,
		},
		Predicate: predicate{
			Verifier: map[string]string{
				"id": "ec",
			},
			TimeVerified: time.Now().String(),
			// need to check on this. Sounds like it should be the same as the subject, but not compatible types
			ResourceUri: subject[0].Name,
			Policies:    verifiedPolicies,
			InputAttestations: []attestationSource{
				{
					digest: digest,
				},
			},
			VerificationResult:  verificationResult,
			VerifiedRules:       verifiedLevels,
			VerifiedCollections: verifiedCollections,
			SlsaVersion:         slsaVersion,
		},
	}, nil
}
