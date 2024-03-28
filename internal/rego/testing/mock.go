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

package testing

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
)

var mocks = map[string]map[int]ast.Value{}

func RegisterMockSupport() {
	decl := rego.Function{
		Name:        "ec.test.mock",
		Description: "Mock a function, available only in tests.",
		Decl: types.NewFunction(
			types.Args(
				types.Named("function", types.S).Description("Function to mock"),
				types.Named("args", types.NewArray(nil, types.A)).Description("Arguments to match"),
				types.Named("return", types.A).Description("Mocked return value"),
			),
			nil,
		),
		Memoize:          false,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin3(&decl, mock)
}

func mock(bctx rego.BuiltinContext, function *ast.Term, args *ast.Term, ret *ast.Term) (*ast.Term, error) {
	f, err := builtins.StringOperand(function.Value, 1)
	if err != nil {
		return nil, err
	}

	fun := string(f)

	m, ok := mocks[fun]

	if !ok {
		m = map[int]ast.Value{}
		mocks[fun] = m
	}

	m[args.Value.Hash()] = ret.Value

	return ast.BooleanTerm(true), nil
}

func Mocked(bctx rego.BuiltinContext, fun string, args *ast.Term) (*ast.Term, bool) {
	m, ok := mocks[fun]
	if !ok {
		return nil, false
	}

	val, ok := m[args.Value.Hash()]
	if !ok {
		return nil, false
	}

	return ast.NewTerm(val), true
}
