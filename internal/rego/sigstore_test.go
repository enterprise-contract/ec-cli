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

//go:build unit

package evaluator

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/enterprise-contract/ec-cli/internal/evaluation_target/application_snapshot_image"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

func TestSigstoreVerifyImage(t *testing.T) {
	goodImage := name.MustParseReference(
		"registry.local/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
	)

	cases := []struct {
		name         string
		success      *ast.Term
		errors       *ast.Term
		uri          *ast.Term
		opts         options
		optsVerifier func(mock.Arguments)
		sigError     error
	}{
		{
			name:    "long lived key",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts:    options{ignoreRekor: true, publicKey: utils.TestPublicKey},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(2).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.True(t, checkOpts.IgnoreTlog)
				require.Nil(t, checkOpts.RekorClient)
				require.Empty(t, checkOpts.Identities)
			},
		},
		{
			name:    "long lived key with rekor",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts:    options{publicKey: utils.TestPublicKey, rekorURL: "https://rekor.local"},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(2).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.Empty(t, checkOpts.Identities)
				require.NotNil(t, checkOpts.RekorClient)
			},
		},
		{
			name:    "fulcio key",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts: options{
				certificateIdentity:   "subject",
				certificateOIDCIssuer: "issuer",
				rekorURL:              "https://rekor.local",
			},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(2).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.NotNil(t, checkOpts.RekorClient)
				identities := []cosign.Identity{{Issuer: "issuer", Subject: "subject"}}
				require.Equal(t, checkOpts.Identities, identities)
			},
		},
		{
			name:    "fulcio key regex",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts: options{
				certificateIdentityRegExp:   `subject.*`,
				certificateOIDCIssuerRegExp: `issuer.*`,
				rekorURL:                    "https://rekor.local",
			},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(2).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.NotNil(t, checkOpts.RekorClient)
				identities := []cosign.Identity{{IssuerRegExp: `issuer.*`, SubjectRegExp: `subject.*`}}
				require.Equal(t, checkOpts.Identities, identities)
			},
		},
		{
			name:    "bad public key",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("opts parameter: new policy: loading URL: unrecognized scheme: spam://"),
			),
			uri:  ast.StringTerm(goodImage.String()),
			opts: options{publicKey: "spam://this-key-does-not-exist"},
		},
		{
			name:    "insufficient options",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("opts parameter: new policy: 2 errors occurred:\n\t* certificate OIDC issuer must be provided for keyless workflow\n\t* certificate identity must be provided for keyless workflow\n\n"),
			),
			uri: ast.StringTerm(goodImage.String()),
		},
		{
			name:    "image ref without digest",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("new digest: a digest must contain exactly one '@' separator (e.g. registry/repository@digest) saw: registry.local/spam:latest"),
			),
			uri: ast.StringTerm("registry.local/spam:latest"),
		},
		{
			name:    "verification failure",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("verify image signature: kaboom!"),
			),
			uri:      ast.StringTerm(goodImage.String()),
			opts:     options{ignoreRekor: true, publicKey: utils.TestPublicKey},
			sigError: errors.New("kaboom!"),
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			utils.SetTestRekorPublicKey(t)
			utils.SetTestFulcioRoots(t)
			utils.SetTestCTLogPublicKey(t)

			c := MockClient{}
			ctx := application_snapshot_image.WithClient(context.Background(), &c)

			verifyCall := c.On(
				"VerifyImageSignatures", ctx, goodImage, mock.Anything,
			).Return([]oci.Signature{}, false, tt.sigError)

			if tt.optsVerifier != nil {
				verifyCall.Run(tt.optsVerifier)
			}

			bctx := rego.BuiltinContext{Context: ctx}

			result, err := sigstoreVerifyImage(bctx, tt.uri, tt.opts.toTerm())
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, tt.errors, result.Get(ast.StringTerm("errors")))
			require.Equal(t, tt.success, result.Get(ast.StringTerm("success")))
		})
	}
}

func TestSigstoreVerifyAttestation(t *testing.T) {
	goodImage := name.MustParseReference(
		"registry.local/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
	)

	cases := []struct {
		name         string
		success      *ast.Term
		errors       *ast.Term
		uri          *ast.Term
		opts         options
		optsVerifier func(mock.Arguments)
		sigError     error
	}{
		{
			name:    "long lived key",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts:    options{ignoreRekor: true, publicKey: utils.TestPublicKey},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(2).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.True(t, checkOpts.IgnoreTlog)
				require.Nil(t, checkOpts.RekorClient)
				require.Empty(t, checkOpts.Identities)
			},
		},
		{
			name:    "long lived key with rekor",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts:    options{publicKey: utils.TestPublicKey, rekorURL: "https://rekor.local"},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(2).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.Empty(t, checkOpts.Identities)
				require.NotNil(t, checkOpts.RekorClient)
			},
		},
		{
			name:    "fulcio key",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts: options{
				certificateIdentity:   "subject",
				certificateOIDCIssuer: "issuer",
				rekorURL:              "https://rekor.local",
			},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(2).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.NotNil(t, checkOpts.RekorClient)
				identities := []cosign.Identity{{Issuer: "issuer", Subject: "subject"}}
				require.Equal(t, checkOpts.Identities, identities)
			},
		},
		{
			name:    "fulcio key regex",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts: options{
				certificateIdentityRegExp:   `subject.*`,
				certificateOIDCIssuerRegExp: `issuer.*`,
				rekorURL:                    "https://rekor.local",
			},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(2).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.NotNil(t, checkOpts.RekorClient)
				identities := []cosign.Identity{{IssuerRegExp: `issuer.*`, SubjectRegExp: `subject.*`}}
				require.Equal(t, checkOpts.Identities, identities)
			},
		},
		{
			name:    "bad public key",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("opts parameter: new policy: loading URL: unrecognized scheme: spam://"),
			),
			uri:  ast.StringTerm(goodImage.String()),
			opts: options{publicKey: "spam://this-key-does-not-exist"},
		},
		{
			name:    "insufficient options",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("opts parameter: new policy: 2 errors occurred:\n\t* certificate OIDC issuer must be provided for keyless workflow\n\t* certificate identity must be provided for keyless workflow\n\n"),
			),
			uri: ast.StringTerm(goodImage.String()),
		},
		{
			name:    "image ref without digest",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("new digest: a digest must contain exactly one '@' separator (e.g. registry/repository@digest) saw: registry.local/spam:latest"),
			),
			uri: ast.StringTerm("registry.local/spam:latest"),
		},
		{
			name:    "verification failure",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("verify image attestation signature: kaboom!"),
			),
			uri:      ast.StringTerm(goodImage.String()),
			opts:     options{ignoreRekor: true, publicKey: utils.TestPublicKey},
			sigError: errors.New("kaboom!"),
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			utils.SetTestRekorPublicKey(t)
			utils.SetTestFulcioRoots(t)
			utils.SetTestCTLogPublicKey(t)

			c := MockClient{}
			ctx := application_snapshot_image.WithClient(context.Background(), &c)

			verifyCall := c.On(
				"VerifyImageAttestations", ctx, goodImage, mock.Anything,
			).Return([]oci.Signature{}, false, tt.sigError)

			if tt.optsVerifier != nil {
				verifyCall.Run(tt.optsVerifier)
			}

			bctx := rego.BuiltinContext{Context: ctx}

			result, err := sigstoreVerifyAttestation(bctx, tt.uri, tt.opts.toTerm())
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, tt.errors, result.Get(ast.StringTerm("errors")))
			require.Equal(t, tt.success, result.Get(ast.StringTerm("success")))
		})
	}
}

type MockClient struct {
	mock.Mock
}

func (c *MockClient) VerifyImageSignatures(ctx context.Context, name name.Reference, opts *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	args := c.Called(ctx, name, opts)

	return args.Get(0).([]oci.Signature), args.Get(1).(bool), args.Error(2)
}

func (c *MockClient) VerifyImageAttestations(ctx context.Context, name name.Reference, opts *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	args := c.Called(ctx, name, opts)

	return args.Get(0).([]oci.Signature), args.Get(1).(bool), args.Error(2)
}

func (c *MockClient) Head(name name.Reference, options ...remote.Option) (*v1.Descriptor, error) {
	args := c.Called(name, options)

	return args.Get(0).(*v1.Descriptor), args.Error(1)
}

func (c *MockClient) ResolveDigest(ref name.Reference, opts *cosign.CheckOpts) (string, error) {
	return "", nil
}
