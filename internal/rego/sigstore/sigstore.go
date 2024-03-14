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

// IMPORTANT: The rego functions in this file never return an error. Instead, they return no value
// when an error is encountered. If they did return an error, opa would exit abruptly and it would
// not produce a report of which policy rules succeeded/failed.

package sigstore

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
	"github.com/sigstore/cosign/v2/pkg/cosign"

	"github.com/enterprise-contract/ec-cli/internal/evaluation_target/application_snapshot_image"
	"github.com/enterprise-contract/ec-cli/internal/policy"
)

const (
	sigstoreVerifyImageName       = "ec.sigstore.verify_image"
	sigstoreVerifyAttestationName = "ec.sigstore.verify_attestation"
)

const (
	certificateIdentityAttribute         = "certificate_identity"
	certificateIdentityRegExpAttribute   = "certificate_identity_regexp"
	certificateOIDCIssuerAttribute       = "certificate_oidc_issuer"
	certificateOIDCIssuerRegExpAttribute = "certificate_oidc_issuer_regexp"
	ignoreRekorAttribute                 = "ignore_rekor"
	publicKeyAttribute                   = "public_key"
	rekorURLAttribute                    = "rekor_url"
)

var ociImageReferenceParameter = types.Named("ref", types.S).Description("OCI image reference")

var sigstoreOptsParameter = types.Named("opts",
	types.NewObject(
		[]*types.StaticProperty{
			{Key: certificateIdentityAttribute, Value: types.S},
			{Key: certificateIdentityRegExpAttribute, Value: types.S},
			{Key: certificateOIDCIssuerAttribute, Value: types.S},
			{Key: certificateOIDCIssuerRegExpAttribute, Value: types.S},
			{Key: ignoreRekorAttribute, Value: types.B},
			{Key: publicKeyAttribute, Value: types.S},
			{Key: rekorURLAttribute, Value: types.S},
		},
		nil,
	)).Description("Sigstore verification options")

// TODO: We want to enhance this verification result to return signatures and attestations. This is
// important, specially for verify_attestation so callers can make sure the expected predicate is
// found. At that time, it may not make sense to share the same result type between the different
// verify_* functions.
var verificationResult = types.Named(
	"result",
	types.NewObject([]*types.StaticProperty{
		{Key: "success", Value: types.Named("success", types.B).Description("true when verification is successful")},
		{Key: "errors", Value: types.Named("errors", types.NewArray([]types.Type{types.S}, nil)).Description("verification errors")},
	}, nil),
).Description("the result of the verification request")

func registerSigstoreVerifyImage() {
	decl := rego.Function{
		Name:        sigstoreVerifyImageName,
		Description: "Use sigstore to verify the signature of an image.",
		Decl: types.NewFunction(
			types.Args(ociImageReferenceParameter, sigstoreOptsParameter),
			verificationResult,
		),
		Memoize:          true,
		Nondeterministic: true,
	}
	rego.RegisterBuiltin2(&decl, sigstoreVerifyImage)
}

func sigstoreVerifyImage(bctx rego.BuiltinContext, refTerm *ast.Term, optsTerm *ast.Term) (*ast.Term, error) {
	ctx := bctx.Context

	uri, err := builtins.StringOperand(refTerm.Value, 0)
	if err != nil {
		return makeVerificationResult(fmt.Sprintf("ref parameter: %s", err)), nil
	}

	ref, err := name.NewDigest(string(uri))
	if err != nil {
		return makeVerificationResult(fmt.Sprintf("new digest: %s", err)), nil
	}

	checkOpts, err := parseCheckOpts(ctx, optsTerm)
	if err != nil {
		return makeVerificationResult(fmt.Sprintf("opts parameter: %s", err)), nil
	}
	checkOpts.ClaimVerifier = cosign.SimpleClaimVerifier

	_, _, err = application_snapshot_image.NewClient(ctx).VerifyImageSignatures(ctx, ref, checkOpts)
	if err != nil {
		return makeVerificationResult(fmt.Sprintf("verify image signature: %s", err)), nil
	}

	return makeVerificationResult(), nil
}

func registerSigstoreVerifyAttestation() {
	decl := rego.Function{
		Name:        sigstoreVerifyAttestationName,
		Description: "Use sigstore to verify the attestation of an image.",
		Decl: types.NewFunction(
			types.Args(ociImageReferenceParameter, sigstoreOptsParameter),
			verificationResult,
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic. But also mark it as non-deterministic because it does rely on external
		// entities, i.e. OCI registry. https://www.openpolicyagent.org/docs/latest/extensions/
		Memoize:          true,
		Nondeterministic: true,
	}
	rego.RegisterBuiltin2(&decl, sigstoreVerifyAttestation)
}

func sigstoreVerifyAttestation(bctx rego.BuiltinContext, refTerm *ast.Term, optsTerm *ast.Term) (*ast.Term, error) {
	ctx := bctx.Context

	uri, err := builtins.StringOperand(refTerm.Value, 0)
	if err != nil {
		return makeVerificationResult(fmt.Sprintf("ref parameter: %s", err)), nil
	}

	ref, err := name.NewDigest(string(uri))
	if err != nil {
		return makeVerificationResult(fmt.Sprintf("new digest: %s", err)), nil
	}

	checkOpts, err := parseCheckOpts(ctx, optsTerm)
	if err != nil {
		return makeVerificationResult(fmt.Sprintf("opts parameter: %s", err)), nil
	}
	checkOpts.ClaimVerifier = cosign.IntotoSubjectClaimVerifier

	_, _, err = application_snapshot_image.NewClient(ctx).VerifyImageAttestations(ctx, ref, checkOpts)
	if err != nil {
		return makeVerificationResult(fmt.Sprintf("verify image attestation signature: %s", err)), nil
	}

	return makeVerificationResult(), nil
}

func parseCheckOpts(ctx context.Context, optsTerm *ast.Term) (*cosign.CheckOpts, error) {
	if _, err := builtins.ObjectOperand(optsTerm.Value, 1); err != nil {
		return nil, fmt.Errorf("opts parameter: %s", err)
	}
	opts := optionsFromTerm(optsTerm)

	policyOpts := policy.Options{
		// TODO: EffectiveTime is not actually used in this context, but it is required to be set
		// by policy.NewPolicy.
		EffectiveTime: "now",
		Identity: cosign.Identity{
			Subject:       opts.certificateIdentity,
			SubjectRegExp: opts.certificateIdentityRegExp,
			Issuer:        opts.certificateOIDCIssuer,
			IssuerRegExp:  opts.certificateOIDCIssuerRegExp,
		},
		IgnoreRekor: opts.ignoreRekor,
		PublicKey:   opts.publicKey,
		RekorURL:    opts.rekorURL,
	}

	policy, err := policy.NewPolicy(ctx, policyOpts)
	if err != nil {
		return nil, fmt.Errorf("new policy: %s", err)
	}

	return policy.CheckOpts()
}

type options struct {
	certificateIdentity         string
	certificateIdentityRegExp   string
	certificateOIDCIssuer       string
	certificateOIDCIssuerRegExp string
	ignoreRekor                 bool
	publicKey                   string
	rekorURL                    string
}

func (o options) toTerm() *ast.Term {
	return ast.ObjectTerm(
		ast.Item(ast.StringTerm(certificateIdentityAttribute), ast.StringTerm(o.certificateIdentity)),
		ast.Item(ast.StringTerm(certificateIdentityRegExpAttribute), ast.StringTerm(o.certificateIdentityRegExp)),
		ast.Item(ast.StringTerm(certificateOIDCIssuerAttribute), ast.StringTerm(o.certificateOIDCIssuer)),
		ast.Item(ast.StringTerm(certificateOIDCIssuerRegExpAttribute), ast.StringTerm(o.certificateOIDCIssuerRegExp)),
		ast.Item(ast.StringTerm(ignoreRekorAttribute), ast.BooleanTerm(o.ignoreRekor)),
		ast.Item(ast.StringTerm(publicKeyAttribute), ast.StringTerm(o.publicKey)),
		ast.Item(ast.StringTerm(rekorURLAttribute), ast.StringTerm(o.rekorURL)),
	)
}

func optionsFromTerm(term *ast.Term) options {
	opts := options{}

	if v, ok := term.Get(ast.StringTerm(certificateIdentityAttribute)).Value.(ast.String); ok {
		opts.certificateIdentity = string(v)
	}

	if v, ok := term.Get(ast.StringTerm(certificateIdentityRegExpAttribute)).Value.(ast.String); ok {
		opts.certificateIdentityRegExp = string(v)
	}

	if v, ok := term.Get(ast.StringTerm(certificateOIDCIssuerAttribute)).Value.(ast.String); ok {
		opts.certificateOIDCIssuer = string(v)
	}

	if v, ok := term.Get(ast.StringTerm(certificateOIDCIssuerRegExpAttribute)).Value.(ast.String); ok {
		opts.certificateOIDCIssuerRegExp = string(v)
	}

	if v, ok := term.Get(ast.StringTerm(ignoreRekorAttribute)).Value.(ast.Boolean); ok {
		opts.ignoreRekor = bool(v)
	}

	if v, ok := term.Get(ast.StringTerm(publicKeyAttribute)).Value.(ast.String); ok {
		opts.publicKey = string(v)
	}

	if v, ok := term.Get(ast.StringTerm(rekorURLAttribute)).Value.(ast.String); ok {
		opts.rekorURL = string(v)
	}

	return opts
}

func makeVerificationResult(errors ...string) *ast.Term {

	var terms []*ast.Term
	for _, err := range errors {
		terms = append(terms, ast.StringTerm(err))
	}
	errorsTerm := ast.ArrayTerm(terms...)

	var success bool
	if len(errors) == 0 {
		success = true
	}

	return ast.ObjectTerm(
		ast.Item(ast.StringTerm("success"), ast.BooleanTerm(success)),
		ast.Item(ast.StringTerm("errors"), errorsTerm),
	)
}

func init() {
	registerSigstoreVerifyImage()
	registerSigstoreVerifyAttestation()
}
