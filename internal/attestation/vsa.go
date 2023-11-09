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

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v2/pkg/cosign"

	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"
)

const (
	// Make it visible elsewhere
	PredicateVSAProvenance = "https://enterprisecontract.dev/verification_summary/v1"
	StatmentVSA            = "https://in-toto.io/Statement/v1"
)

type ImageResolver interface {
	FetchDigest() (name.Digest, error)
	ResolveAttestationTag(name.Reference, ...remote.Option) (name.Tag, error)
	ResolveSBOMTag(name.Reference, ...remote.Option) (name.Tag, error)
	GetReference() name.Reference
	FetchImageDigest(string) (name.Digest, error)
	Attestations() []Attestation
}

type ProvenanceStatementVSA struct {
	in_toto.StatementHeader
	Predicate predicate `json:"predicate"`
}

type policySource struct {
	Uri string `json:"uri,omitempty"`
}

type attestationSource struct {
	Version string            `json:"version,omitempty"`
	Uri     string            `json:"uri,omitempty"`
	Digest  map[string]string `json:"digest,omitempty"`
}

type predicate struct {
	Verifier            map[string]string   `json:"verifier,omitempty"`
	TimeVerified        string              `json:"timeVerified,omitempty"`
	ResourceUri         string              `json:"resourceUri"`
	Policies            []policySource      `json:"policies,omitempty"`
	InputAttestations   []attestationSource `json:"inputAttestations,omitempty"`
	VerificationResult  string              `json:"verificationResult,omitempty"`
	VerifiedRules       []string            `json:"verifiedRules,omitempty"`
	VerifiedCollections []string            `json:"verfiedCollection,omitempty"`
}

func VsaFromImageValidation(resolver ImageResolver, verifiedTime string, results []evaluator.Outcome, policies []source.PolicySource, policy policy.Policy) (*ProvenanceStatementVSA, error) {
	var verifiedPolicies []policySource
	for _, p := range policies {
		verifiedPolicies = append(verifiedPolicies, policySource{Uri: p.PolicyUrl()})
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

	var subjects []in_toto.Subject
	var inputAttestations []attestationSource

	for _, sp := range resolver.Attestations() {
		attSource, err := fetchAttestationSource(resolver, sp.PredicateType())
		if err != nil {
			return nil, err
		}
		inputAttestations = append(inputAttestations, attSource)
		subjects = append(subjects, sp.Subject()...)
	}

	return &ProvenanceStatementVSA{
		StatementHeader: in_toto.StatementHeader{
			Type:          StatmentVSA,
			PredicateType: PredicateVSAProvenance,
			Subject:       subjects,
		},
		Predicate: predicate{
			Verifier: map[string]string{
				"id": "ec",
			},
			TimeVerified:        verifiedTime,
			ResourceUri:         resolver.GetReference().Name(),
			Policies:            verifiedPolicies,
			InputAttestations:   inputAttestations,
			VerificationResult:  verificationResult,
			VerifiedRules:       verifiedLevels,
			VerifiedCollections: verifiedCollections,
		},
	}, nil
}

func fetchAttestationSource(resolver ImageResolver, attType string) (attestationSource, error) {
	var attSource attestationSource

	opts := cosign.CheckOpts{}
	digest, err := resolver.FetchDigest()
	if err != nil {
		return attSource, err
	}

	var st name.Tag
	var stErr error
	switch attType {
	case PredicateSLSAProvenance:
		st, stErr = resolver.ResolveAttestationTag(digest, opts.RegistryClientOpts...)
		if stErr != nil {
			return attSource, stErr
		}
	case PredicateSpdxDocument:
		st, stErr = resolver.ResolveSBOMTag(digest, opts.RegistryClientOpts...)
		if stErr != nil {
			return attSource, stErr
		}
	}

	attDigest, err := resolver.FetchImageDigest(st.Name())
	if err != nil {
		return attSource, err
	}
	attSource.Digest = map[string]string{"sha256": attDigest.DigestStr()}
	attSource.Uri = st.Name()
	attSource.Version = attType

	return attSource, nil
}

// func fetchDigest(img string) (name.Digest, error) {
// 	var digest name.Digest
// 	opts := cosign.CheckOpts{}
// 	attRef, err := name.ParseReference(img)
// 	if err != nil {
// 		return digest, err
// 	}

// 	digest, err = remote.ResolveDigest(attRef, opts.RegistryClientOpts...)
// 	if err != nil {
// 		return digest, err
// 	}
// 	return digest, nil
// }
