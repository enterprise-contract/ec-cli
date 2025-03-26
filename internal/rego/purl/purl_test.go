// Copyright The Conforma Contributors
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

package rego

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/require"
)

func TestPURLIsValid(t *testing.T) {
	cases := []struct {
		name     string
		uri      *ast.Term
		expected bool
	}{
		{
			name:     "success",
			uri:      ast.StringTerm("pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25"),
			expected: true,
		},
		{
			name:     "unexpected uri type",
			uri:      ast.IntNumberTerm(42),
			expected: false,
		},
		{
			name:     "malformed PURL string",
			uri:      ast.StringTerm("pkg::rpm//fedora/curl7.50.3-1.fc25?arch=i386&distro=fedora-"),
			expected: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			bctx := rego.BuiltinContext{Context: ctx}

			isValid, err := purlIsValid(bctx, c.uri)
			require.NoError(t, err)
			require.NotNil(t, isValid)
			require.Equal(t, isValid, ast.BooleanTerm(c.expected))
		})
	}
}

func TestPURLParse(t *testing.T) {
	cases := []struct {
		name string
		uri  *ast.Term
		err  bool
	}{
		{
			name: "success",
			uri:  ast.StringTerm("pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25"),
		},
		{
			name: "unexpected uri type",
			uri:  ast.IntNumberTerm(42),
			err:  true,
		},
		{
			name: "malformed PURL string",
			uri:  ast.StringTerm("pkg::rpm//fedora/curl7.50.3-1.fc25?arch=i386&distro=fedora-"),
			err:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			bctx := rego.BuiltinContext{Context: ctx}

			instance, err := purlParse(bctx, c.uri)
			require.NoError(t, err)
			if c.err {
				require.Nil(t, instance)
			} else {
				require.NotNil(t, instance)
				data := instance.Get(ast.StringTerm("type")).Value
				require.Equal(t, ast.String("rpm"), data)
			}
		})
	}
}

func TestFunctionsRegistered(t *testing.T) {
	names := []string{
		purlIsValidName,
		purlParseName,
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			for _, builtin := range ast.Builtins {
				if builtin.Name == name {
					return
				}
			}
			t.Fatalf("%s builtin not registered", name)
		})
	}
}
