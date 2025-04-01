// Copyright The Conforma Contributors
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
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"

	"github.com/enterprise-contract/ec-cli/internal/attestation"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/signature"
	ecoci "github.com/enterprise-contract/ec-cli/internal/utils/oci"
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

func registerSigstoreVerifyImage() {
	result := types.Named(
		"result",
		types.NewObject([]*types.StaticProperty{
			{Key: "success", Value: types.Named("success", types.B).Description("true when verification is successful")},
			{Key: "errors", Value: types.Named("errors", types.NewArray([]types.Type{types.S}, nil)).Description("verification errors")},
			{Key: "signatures", Value: types.Named("signatures", types.NewArray([]types.Type{signatureType}, nil)).Description("matching signatures")},
		}, nil),
	).Description("the result of the verification request")

	decl := rego.Function{
		Name:        sigstoreVerifyImageName,
		Description: "Use sigstore to verify the signature of an image.",
		Decl: types.NewFunction(
			types.Args(ociImageReferenceParameter, sigstoreOptsParameter),
			result,
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
		return signatureFailedResult(fmt.Errorf("ref parameter: %w", err))
	}

	ref, err := name.NewDigest(string(uri))
	if err != nil {
		return signatureFailedResult(fmt.Errorf("new digest: %w", err))
	}

	checkOpts, err := parseCheckOpts(ctx, optsTerm)
	if err != nil {
		return signatureFailedResult(fmt.Errorf("opts parameter: %w", err))
	}
	checkOpts.ClaimVerifier = cosign.SimpleClaimVerifier

	signatures, _, err := ecoci.NewClient(ctx).VerifyImageSignatures(ref, checkOpts)
	if err != nil {
		return signatureFailedResult(fmt.Errorf("verify image signature: %w", err))
	}

	return signatureResult(signatures, nil)
}

func registerSigstoreVerifyAttestation() {
	attestationType := types.Named("attestation", types.NewObject([]*types.StaticProperty{
		{Key: "statement", Value: types.Named("statement", types.A).Description("statement from attestation")},
		{Key: "signatures", Value: types.Named(
			"signatures",
			types.NewArray([]types.Type{signatureType}, nil),
		).Description("signatures associated with attestation")},
	}, nil)).Description("attestation matching provided identity/key")

	result := types.Named(
		"result",
		types.NewObject([]*types.StaticProperty{
			{Key: "success", Value: types.Named("success", types.B).Description("true when verification is successful")},
			{Key: "errors", Value: types.Named("errors", types.NewArray([]types.Type{types.S}, nil)).Description("verification errors")},
			{Key: "attestations", Value: types.Named("attestations", types.NewArray([]types.Type{attestationType}, nil)).Description("matching attestations")},
		}, nil),
	).Description("the result of the verification request")

	decl := rego.Function{
		Name:        sigstoreVerifyAttestationName,
		Description: "Use sigstore to verify the attestation of an image.",
		Decl: types.NewFunction(
			types.Args(ociImageReferenceParameter, sigstoreOptsParameter),
			result,
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
		return attestationFailedResult(fmt.Errorf("ref parameter: %w", err))
	}

	ref, err := name.NewDigest(string(uri))
	if err != nil {
		return attestationFailedResult(fmt.Errorf("new digest: %w", err))
	}

	checkOpts, err := parseCheckOpts(ctx, optsTerm)
	if err != nil {
		return attestationFailedResult(fmt.Errorf("opts parameter: %w", err))
	}
	checkOpts.ClaimVerifier = cosign.IntotoSubjectClaimVerifier

	attestations, _, err := ecoci.NewClient(ctx).VerifyImageAttestations(ref, checkOpts)
	if err != nil {
		return attestationFailedResult(fmt.Errorf("verify image attestation signature: %w", err))
	}

	return attestationResult(attestations, nil)
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

func signatureFailedResult(err error) (*ast.Term, error) {
	return signatureResult(nil, err)
}

func signatureResult(signatures []oci.Signature, err error) (*ast.Term, error) {
	var errorTerms []*ast.Term
	var sigTerms []*ast.Term

	if err != nil {
		errorTerms = append(errorTerms, ast.StringTerm(err.Error()))
	}

	for _, s := range signatures {
		sig, err := signature.NewEntitySignature(s)
		if err != nil {
			errorTerms = append(errorTerms, ast.StringTerm(fmt.Sprintf("parsing signature: %s", err)))
			continue
		}

		sigTerms = append(sigTerms, toSignatureTerm(sig))
	}

	success := len(errorTerms) == 0

	return ast.ObjectTerm(
		ast.Item(ast.StringTerm("success"), ast.BooleanTerm(success)),
		ast.Item(ast.StringTerm("errors"), ast.ArrayTerm(errorTerms...)),
		ast.Item(ast.StringTerm("signatures"), ast.ArrayTerm(sigTerms...)),
	), nil
}

func attestationFailedResult(err error) (*ast.Term, error) {
	return attestationResult(nil, err)
}

func attestationResult(attestations []oci.Signature, err error) (*ast.Term, error) {
	var errorTerms []*ast.Term
	var attestationTerms []*ast.Term

	if err != nil {
		errorTerms = append(errorTerms, ast.StringTerm(err.Error()))
	}

	for _, s := range attestations {
		att, err := attestation.ProvenanceFromSignature(s)
		if err != nil {
			errorTerms = append(errorTerms, ast.StringTerm(fmt.Sprintf("parsing attestation: %s", err)))
			continue
		}

		var statement any
		if err := json.Unmarshal(att.Statement(), &statement); err != nil {
			errorTerms = append(errorTerms, ast.StringTerm(fmt.Sprintf("unmarshalling statement: %s", err)))
			continue
		}

		statementValue, err := ast.InterfaceToValue(statement)
		if err != nil {
			errorTerms = append(errorTerms, ast.StringTerm(fmt.Sprintf("interface to value: %s", err)))
			continue
		}

		var sigsTerm []*ast.Term
		for _, sig := range att.Signatures() {
			sigsTerm = append(sigsTerm, toSignatureTerm(sig))
		}

		attestationTerms = append(attestationTerms, ast.ObjectTerm(
			ast.Item(ast.StringTerm("statement"), ast.NewTerm(statementValue)),
			ast.Item(ast.StringTerm("signatures"), ast.ArrayTerm(sigsTerm...)),
		))
	}

	success := len(errorTerms) == 0

	return ast.ObjectTerm(
		ast.Item(ast.StringTerm("success"), ast.BooleanTerm(success)),
		ast.Item(ast.StringTerm("errors"), ast.ArrayTerm(errorTerms...)),
		ast.Item(ast.StringTerm("attestations"), ast.ArrayTerm(attestationTerms...)),
	), nil
}

func init() {
	registerSigstoreVerifyImage()
	registerSigstoreVerifyAttestation()
}
