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

package evaluator

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"github.com/package-url/packageurl-go"
	log "github.com/sirupsen/logrus"

	"github.com/enterprise-contract/ec-cli/internal/fetchers/oci"
)

const ociBlobName = "ec.oci.blob"
const purlIsValidName = "ec.purl.is_valid"
const purlParseName = "ec.purl.parse"

func registerOCIBlob() {
	decl := rego.Function{
		Name: ociBlobName,
		Decl: types.NewFunction(
			types.Args(
				types.Named("ref", types.S).Description("OCI blob reference"),
			),
			types.Named("blob", types.S).Description("the OCI blob"),
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic. But also mark it as non-deterministic because it does rely on external
		// entities, i.e. OCI registry. https://www.openpolicyagent.org/docs/latest/extensions/
		Memoize:          true,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin1(&decl, ociBlob)
	// Due to https://github.com/open-policy-agent/opa/issues/6449, we cannot set a description for
	// the custom function through the call above. As a workaround we re-register the function with
	// a declaration that does include the description.
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      "Fetch a blob from an OCI registry.",
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
}

func registerPURLIsValid() {
	decl := rego.Function{
		Name: purlIsValidName,
		Decl: types.NewFunction(
			types.Args(
				types.Named("purl", types.S).Description("the PURL"),
			),
			types.Named("result", types.S).Description("PURL validity"),
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic.
		Memoize:          true,
		Nondeterministic: false,
	}

	rego.RegisterBuiltin1(&decl, purlIsValid)
	// Due to https://github.com/open-policy-agent/opa/issues/6449, we cannot set a description for
	// the custom function through the call above. As a workaround we re-register the function with
	// a declaration that does include the description.
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      "Determine whether or not a given PURL is valid.",
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
}

func registerPURLParse() {
	decl := rego.Function{
		Name: purlParseName,
		Decl: types.NewFunction(
			types.Args(
				types.Named("purl", types.S).Description("the PURL"),
			),
			types.Named("object", types.NewObject(
				[]*types.StaticProperty{
					// Specifying the properties like this ensure the compiler catches typos when
					// evaluating rego functions.
					{Key: "type", Value: types.S},
					{Key: "namespace", Value: types.S},
					{Key: "name", Value: types.S},
					{Key: "version", Value: types.S},
					{Key: "qualifiers", Value: types.NewArray(
						nil, types.NewObject(
							[]*types.StaticProperty{
								{Key: "key", Value: types.S},
								{Key: "value", Value: types.S},
							},
							nil,
						),
					)},
					{Key: "subpath", Value: types.S},
				},
				nil,
			)).Description("the parsed PURL object"),
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic.
		Memoize:          true,
		Nondeterministic: false,
	}

	rego.RegisterBuiltin1(&decl, purlParse)
	// Due to https://github.com/open-policy-agent/opa/issues/6449, we cannot set a description for
	// the custom function through the call above. As a workaround we re-register the function with
	// a declaration that does include the description.
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      "Parse a valid PURL into an object.",
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
}

const maxBytes = 10 * 1024 * 1024 // 10 MB

func ociBlob(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	uri, ok := a.Value.(ast.String)
	if !ok {
		return nil, nil
	}

	ref, err := name.NewDigest(string(uri))
	if err != nil {
		log.Errorf("%s new digest: %s", ociBlobName, err)
		return nil, nil
	}

	opts := []remote.Option{
		remote.WithTransport(remote.DefaultTransport),
		remote.WithContext(bctx.Context),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}

	rawLayer, err := oci.NewClient(bctx.Context).Layer(ref, opts...)
	if err != nil {
		log.Errorf("%s fetch layer: %s", ociBlobName, err)
		return nil, nil
	}

	layer, err := rawLayer.Uncompressed()
	if err != nil {
		log.Errorf("%s layer uncompressed: %s", ociBlobName, err)
		return nil, nil
	}
	defer layer.Close()

	// TODO: Other algorithms are technically supported, e.g. sha512. However, support for those is
	// not complete in the go-containerregistry library, e.g. name.NewDigest throws an error if
	// sha256 is not used. This is good for now, but may need revisiting later.
	hasher := sha256.New()
	// Setup some safeguards. First, use LimitReader to avoid an unbounded amount of data from being
	// read. Second, use TeeReader so we can compute the digest of the content read.
	reader := io.TeeReader(io.LimitReader(layer, maxBytes), hasher)

	var blob bytes.Buffer
	if _, err := io.Copy(&blob, reader); err != nil {
		log.Errorf("%s copy buffer: %s", ociBlobName, err)
		return nil, nil
	}

	sum := fmt.Sprintf("sha256:%x", hasher.Sum(nil))
	// io.LimitReader truncates the layer if it exceeds its limit. The condition below catches this
	// scenario in order to avoid unexpected behavior caused by partial data being returned.
	if sum != ref.DigestStr() {
		log.Errorf(
			"%s computed digest, %q, not as expected, %q. Content may have been truncated at %d bytes",
			ociBlobName, sum, ref.DigestStr(), maxBytes)
		return nil, nil
	}

	return ast.StringTerm(blob.String()), nil
}

func purlIsValid(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	uri, ok := a.Value.(ast.String)
	if !ok {
		return ast.BooleanTerm(false), nil
	}
	_, err := packageurl.FromString(string(uri))
	if err != nil {
		log.Errorf("Parsing PURL %s failed: %s", uri, err)
		return ast.BooleanTerm(false), nil
	}
	return ast.BooleanTerm(true), nil
}

func purlParse(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	uri, ok := a.Value.(ast.String)
	if !ok {
		return nil, nil
	}
	instance, err := packageurl.FromString(string(uri))
	if err != nil {
		log.Errorf("Parsing PURL %s failed: %s", uri, err)
		return nil, nil
	}

	qualifiers := ast.NewArray()
	for _, q := range instance.Qualifiers {
		o := ast.NewObject(
			ast.Item(ast.StringTerm("key"), ast.StringTerm(q.Key)),
			ast.Item(ast.StringTerm("value"), ast.StringTerm(q.Value)),
		)
		qualifiers = qualifiers.Append(ast.NewTerm(o))
	}
	return ast.ObjectTerm(
		ast.Item(ast.StringTerm("type"), ast.StringTerm(instance.Type)),
		ast.Item(ast.StringTerm("namespace"), ast.StringTerm(instance.Namespace)),
		ast.Item(ast.StringTerm("name"), ast.StringTerm(instance.Name)),
		ast.Item(ast.StringTerm("version"), ast.StringTerm(instance.Version)),
		ast.Item(ast.StringTerm("qualifiers"), ast.NewTerm(qualifiers)),
		ast.Item(ast.StringTerm("subpath"), ast.StringTerm(instance.Subpath)),
	), nil
}

func init() {
	registerOCIBlob()
	registerPURLIsValid()
	registerPURLParse()
}
