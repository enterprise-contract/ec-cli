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

//go:build unit

package sigstore

import (
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/signature"
)

func TestToSignatureTerm(t *testing.T) {
	es := signature.EntitySignature{
		KeyID:       "the-key-id",
		Signature:   "the-signature",
		Certificate: "the-certificate",
		Chain:       []string{"the-certificate-0", "the-certificate-1"},
		Metadata: map[string]string{
			"the-key-0": "the-value-0",
			"the-key-1": "the-value-1",
		},
	}

	sig := toSignatureTerm(es)

	require.Equal(t, ast.String("the-key-id"), sig.Get(ast.StringTerm("keyid")).Value)
	require.Equal(t, ast.String("the-signature"), sig.Get(ast.StringTerm("signature")).Value)
	require.Equal(t, ast.String("the-certificate"), sig.Get(ast.StringTerm("certificate")).Value)

	chain := sig.Get(ast.StringTerm("chain"))
	require.Equal(t, ast.String("the-certificate-0"), chain.Get(ast.NumberTerm("0")).Value)
	require.Equal(t, ast.String("the-certificate-1"), chain.Get(ast.NumberTerm("1")).Value)

	metadata := sig.Get(ast.StringTerm("metadata"))
	require.Equal(t, ast.String("the-value-0"), metadata.Get(ast.StringTerm("the-key-0")).Value)
	require.Equal(t, ast.String("the-value-1"), metadata.Get(ast.StringTerm("the-key-1")).Value)
}
