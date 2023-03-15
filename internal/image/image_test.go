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
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/attestation"
)

func Test_ValidateImage(t *testing.T) {
	verifySignaturesfunc := func(context.Context, name.Reference, *cosign.CheckOpts) (checkedAttestations []oci.Signature, bundleVerified bool, err error) {
		return []oci.Signature{}, true, nil
	}

	verifyAttestationsfunc := func(context.Context, name.Reference, *cosign.CheckOpts) (checkedAttestations []oci.Signature, bundleVerified bool, err error) {
		return []oci.Signature{}, true, nil
	}

	image := "quay.io/hacbs/image:latest"
	ref, _ := name.ParseReference(image)
	validator := &imageValidator{
		reference:          ref,
		checkOpts:          cosign.CheckOpts{},
		verifySignatures:   verifySignaturesfunc,
		verifyAttestations: verifyAttestationsfunc,
	}

	validated := &validatedImage{
		Reference:    ref,
		Attestations: []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{},
		Signatures:   []oci.Signature{},
	}

	got, err := validator.ValidateImage(context.TODO())
	assert.NoError(t, err)
	assert.Equal(t, validated, got)
}
