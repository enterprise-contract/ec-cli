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
	"context"
	"encoding/json"
	"errors"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/policy"
	"github.com/sigstore/cosign/pkg/signature"
)

type imageValidator struct {
	reference    name.Reference
	checkOpts    cosign.CheckOpts
	attestations []oci.Signature
}

type validatedImage struct {
	Reference    name.Reference
	Attestations []attestation
	Signatures   []oci.Signature
}

// NewImageValidator constructs a new imageValidator with the provided parameters
func NewImageValidator(ctx context.Context, image string, publicKey string, rekorURL string) (*imageValidator, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, err
	}

	verifier, err := signature.PublicKeyFromKeyRef(ctx, publicKey)
	if err != nil {
		return nil, err
	}

	checkOpts := cosign.CheckOpts{}
	checkOpts.SigVerifier = verifier

	if rekorURL != "" {
		rekorClient, err := rekor.NewClient(rekorURL)
		if err != nil {
			return nil, err
		}

		checkOpts.RekorClient = rekorClient
	}

	return &imageValidator{
		reference: ref,
		checkOpts: checkOpts,
	}, nil
}

func (i *imageValidator) ValidateImageSignature(ctx context.Context) error {
	// TODO check what to do with _, _
	_, _, err := cosign.VerifyImageSignatures(ctx, i.reference, &i.checkOpts)

	return err
}

func (i *imageValidator) ValidateAttestationSignature(ctx context.Context) error {
	// TODO check what to do with _
	attestations, _, err := cosign.VerifyImageAttestations(ctx, i.reference, &i.checkOpts)
	if err != nil {
		return err
	}

	i.attestations = attestations

	return nil
}

func (i *imageValidator) ValidateImage(ctx context.Context) (*validatedImage, error) {
	signatures, _, err := cosign.VerifyImageSignatures(ctx, i.reference, &i.checkOpts)
	if err != nil {
		return nil, err
	}

	attestations, _, err := cosign.VerifyImageAttestations(ctx, i.reference, &i.checkOpts)
	attStatements := make([]attestation, 0, len(attestations))
	for _, att := range attestations {
		attStatement, err := signatureToAttestation(ctx, att)
		if err != nil {
			return nil, err
		}
		attStatements = append(attStatements, attStatement)

	}
	if err != nil {
		return nil, err
	}

	return &validatedImage{
		i.reference,
		attStatements,
		signatures,
	}, nil

}

func signatureToAttestation(ctx context.Context, signature oci.Signature) (attestation, error) {
	var att attestation
	payload, err := policy.AttestationToPayloadJSON(ctx, "slsaprovenance", signature)
	if err != nil {
		return attestation{}, err
	}

	if len(payload) == 0 {
		return attestation{}, errors.New("predicate (slsaprovenance) did not match the attestation.")
	}

	err = json.Unmarshal(payload, &att)
	if err != nil {
		return attestation{}, err
	}

	return att, nil
}

func (i *imageValidator) Attestations() []oci.Signature {
	return i.attestations
}
