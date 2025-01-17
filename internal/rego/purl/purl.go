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

package rego

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
	"github.com/package-url/packageurl-go"
	log "github.com/sirupsen/logrus"
)

const (
	purlIsValidName = "ec.purl.is_valid"
	purlParseName   = "ec.purl.parse"
)

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

func purlIsValid(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	uri, ok := a.Value.(ast.String)
	if !ok {
		return ast.BooleanTerm(false), nil
	}
	_, err := packageurl.FromString(string(uri))
	if err != nil {
		log.Debugf("Parsing PURL %s failed: %s", uri, err)
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
	registerPURLIsValid()
	registerPURLParse()
}
