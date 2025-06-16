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

package sigstore

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/types"

	"github.com/conforma/cli/internal/signature"
)

var signatureType = types.NewObject([]*types.StaticProperty{
	{Key: "keyid", Value: types.S},
	{Key: "signature", Value: types.S},
	{Key: "certificate", Value: types.S},
	{Key: "chain", Value: types.NewArray([]types.Type{types.S}, nil)},
	{Key: "metadata", Value: types.NewObject(nil, &types.DynamicProperty{Key: types.S, Value: types.S})},
}, nil)

func toSignatureTerm(sig signature.EntitySignature) *ast.Term {
	var chain []*ast.Term
	for _, cert := range sig.Chain {
		chain = append(chain, ast.StringTerm(cert))
	}

	var metadata [][2]*ast.Term
	for k, v := range sig.Metadata {
		metadata = append(metadata, ast.Item(ast.StringTerm(k), ast.StringTerm(v)))
	}

	return ast.ObjectTerm(
		ast.Item(ast.StringTerm("keyid"), ast.StringTerm(sig.KeyID)),
		ast.Item(ast.StringTerm("signature"), ast.StringTerm(sig.Signature)),
		ast.Item(ast.StringTerm("certificate"), ast.StringTerm(sig.Certificate)),
		ast.Item(ast.StringTerm("chain"), ast.ArrayTerm(chain...)),
		ast.Item(ast.StringTerm("metadata"), ast.ObjectTerm(metadata...)),
	)
}
