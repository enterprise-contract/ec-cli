// Copyright 2023 Red Hat, Inc.
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

package signature

import (
	"context"
	"errors"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/types"
	confOutput "github.com/open-policy-agent/conftest/output"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	cosignTypes "github.com/sigstore/cosign/v2/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/enterprise-contract/ec-cli/internal/certificate"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/sigstore"
	"github.com/enterprise-contract/ec-cli/internal/utils"
	"github.com/enterprise-contract/ec-cli/internal/validator"
)

func TestValidateSuccess(t *testing.T) {
	ref := name.MustParseReference("registry.io/repository/image:tag")

	ctx := context.Background()

	client := MockClient{}
	s := makeTestSignature(t)
	ctx = sigstore.WithClient(ctx, &client)
	client.On("VerifyImageSignatures", ctx, ref, mock.Anything).Return([]oci.Signature{s}, false, nil)

	validator := SignatureValidator{opts: validator.Options{Policy: makeTestPolicy(t, ctx)}}
	result := validator.Validate(ctx, ref)

	snaps.MatchSnapshot(t, result)
}

func TestValidateViolation(t *testing.T) {
	testcases := []struct {
		name               string
		sigError           error
		expectedViolations []confOutput.Result
	}{
		{
			name:     "any error",
			sigError: errors.New("Oh no!"),
			expectedViolations: []confOutput.Result{
				{
					Message: "Image signature check failed: Oh no!",
					Metadata: map[string]any{
						"code":  "builtin.image.signature_check",
						"title": "Image signature check passed",
					},
				},
			},
		},
		{
			name:     "sigstore wrapped error",
			sigError: makeCosignError("no signatures found", cosign.ErrNoMatchingSignaturesType),
			expectedViolations: []confOutput.Result{
				{
					Message: "No image signatures found matching the given public key. " +
						"Verify the correct public key was provided, " +
						"and a signature was created.",
					Metadata: map[string]any{
						"code":  "builtin.image.signature_check",
						"title": "Image signature check passed",
					},
				},
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			ref := name.MustParseReference("registry.io/repository/image:tag")

			ctx := context.Background()

			client := MockClient{}
			ctx = sigstore.WithClient(ctx, &client)
			client.On(
				"VerifyImageSignatures", ctx, ref, mock.Anything,
			).Return(
				[]oci.Signature{}, false, tt.sigError,
			)

			validator := SignatureValidator{opts: validator.Options{Policy: makeTestPolicy(t, ctx)}}
			result := validator.Validate(ctx, ref)

			assert.Equal(t, tt.expectedViolations, result.Violations)

			assert.Empty(t, result.Warnings)
			assert.Empty(t, result.Successes)
			assert.Empty(t, result.Signatures)
		})
	}
}

func makeTestSignature(t *testing.T) oci.Signature {
	signature, err := static.NewSignature(
		[]byte(`image`),
		"signature",
		static.WithLayerMediaType(types.MediaType((cosignTypes.DssePayloadType))),
		static.WithCertChain(
			[]byte(certificate.ChainguardReleaseCert),
			[]byte(certificate.SigstoreChainCert),
		),
	)
	require.NoError(t, err)
	return signature
}

func makeTestPolicy(t *testing.T, ctx context.Context) policy.Policy {
	policy, err := policy.NewPolicy(
		ctx, "", "", utils.TestPublicKey, policy.Now, cosign.Identity{})
	require.NoError(t, err)
	return policy
}

func makeCosignError(msg string, errType string) error {
	e := cosign.NewVerificationError(msg)
	ve := e.(*cosign.VerificationError)
	ve.SetErrorType(errType)
	return ve
}

// TODO: Test claim verifiers - should that be an acceptance test instead?

type MockClient struct {
	mock.Mock
}

func (c *MockClient) VerifyImageSignatures(ctx context.Context, name name.Reference, opts *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	args := c.Called(ctx, name, opts)

	return args.Get(0).([]oci.Signature), args.Get(1).(bool), args.Error(2)
}

func (c *MockClient) VerifyImageAttestations(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	panic("not implemented!")
}
