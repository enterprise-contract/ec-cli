// Copyright 2022 Red Hat, Inc.
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

package rule

import (
	"fmt"
	"testing"

	"github.com/MakeNowJust/heredoc"
	"github.com/open-policy-agent/opa/ast"
	"github.com/stretchr/testify/assert"
)

func annotationRef(rego string) *ast.AnnotationsRef {
	module := ast.MustParseModuleWithOpts(rego, ast.ParserOptions{
		ProcessAnnotation: true,
	})

	if len(module.Annotations) == 0 {
		return nil
	}

	// first rule
	return ast.NewAnnotationsRef(module.Annotations[0])
}

func TestTitle(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   string
	}{
		{
			name:       "no code",
			annotation: nil,
			expected:   "",
		},
		{
			name: "no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				deny() { true }`)),
			expected: "",
		},
		{
			name: "with custom annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# custom:
				#   hmm: 14
				deny() { true }`)),
			expected: "",
		},
		{
			name: "with title annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# title: title
				deny() { true }`)),
			expected: "title",
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, title(c.annotation))
		})
	}
}

func TestDescription(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   string
	}{
		{
			name:       "no code",
			annotation: nil,
			expected:   "",
		},
		{
			name: "no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				deny() { true }`)),
			expected: "",
		},
		{
			name: "with custom annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# custom:
				#   hmm: 14
				deny() { true }`)),
			expected: "",
		},
		{
			name: "with title annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# description: description
				deny() { true }`)),
			expected: "description",
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, description(c.annotation))
		})
	}
}

func TestKind(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   RuleKind
	}{
		{
			name:       "no code",
			annotation: nil,
			expected:   Other,
		},
		{
			name: "other rule",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# title: test
				helper() { true }`)),
			expected: Other,
		},
		{
			name: "deny rule",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# title: test
				deny() { true }`)),
			expected: Deny,
		},
		{
			name: "warn rule",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# title: test
				warn() { true }`)),
			expected: Warn,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, kind(c.annotation))
		})
	}
}

func TestShortName(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   string
	}{
		{
			name:       "no code",
			annotation: nil,
			expected:   "",
		},
		{
			name: "no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				deny() { true }`)),
			expected: "",
		},
		{
			name: "without custom annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# title: title
				deny() { true }`)),
			expected: "",
		},
		{
			name: "with custom annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# custom:
				#   hmm: 14
				deny() { true }`)),
			expected: "",
		},
		{
			name: "with short_name annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# custom:
				#   short_name: here
				deny() { true }`)),
			expected: "here",
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, shortName(c.annotation))
		})
	}
}

func TestCollections(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   []string
	}{
		{
			name:       "no code",
			annotation: nil,
			expected:   []string{},
		},
		{
			name: "no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				deny() { true }`)),
			expected: []string{},
		},
		{
			name: "without custom annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# title: title
				deny() { true }`)),
			expected: []string{},
		},
		{
			name: "with custom annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# custom:
				#   hmm: 14
				deny() { true }`)),
			expected: []string{},
		},
		{
			name: "with one collection annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# custom:
				#   collections:
				#     - A
				deny() { true }`)),
			expected: []string{"A"},
		},
		{
			name: "with several collection annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# custom:
				#   collections:
				#     - A
				#     - B
				#     - C
				deny() { true }`)),
			expected: []string{"A", "B", "C"},
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, collections(c.annotation))
		})
	}
}

func TestCode(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   string
	}{
		{
			name:       "no code",
			annotation: nil,
			expected:   "",
		},
		{
			name: "no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				deny() { true }`)),
			expected: "",
		},
		{
			name: "with short_name",
			annotation: annotationRef(heredoc.Doc(`
				package a
				# METADATA
				# custom:
				#   short_name: x
				deny() { true }`)),
			expected: "a.x",
		},
		{
			name: "nested packages no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a.b.c
				deny() { true }`)),
			expected: "",
		},
		{
			name: "nested packages with short_name",
			annotation: annotationRef(heredoc.Doc(`
				package a.b.c
				# METADATA
				# custom:
				#   short_name: x
				deny() { true }`)),
			expected: "a.b.c.x",
		},
		{
			name: "nested packages with policy package",
			annotation: annotationRef(heredoc.Doc(`
				package policy.a.b.c
				# METADATA
				# custom:
				#   short_name: x
				deny() { true }`)),
			expected: "a.b.c.x",
		},
		{
			name: "nested packages with policy.data package",
			annotation: annotationRef(heredoc.Doc(`
				package policy.data.a.b.c
				# METADATA
				# custom:
				#   short_name: x
				deny() { true }`)),
			expected: "data.a.b.c.x",
		},
		{
			name: "nested packages with data package in regular part",
			annotation: annotationRef(heredoc.Doc(`
				package a.data.b.c
				# METADATA
				# custom:
				#   short_name: x
				deny() { true }`)),
			expected: "a.data.b.c.x",
		},
		{
			name: "nested packages with policy package in regular part",
			annotation: annotationRef(heredoc.Doc(`
				package a.policy.b.c
				# METADATA
				# custom:
				#   short_name: x
				deny() { true }`)),
			expected: "a.policy.b.c.x",
		},
		{
			name: "release category",
			annotation: annotationRef(heredoc.Doc(`
				package policy.release.a.b.c
				# METADATA
				# custom:
				#   short_name: x
				deny() { true }`)),
			expected: "a.b.c.x",
		},
		{
			name: "pipeline category",
			annotation: annotationRef(heredoc.Doc(`
				package policy.pipeline.a.b.c
				# METADATA
				# custom:
				#   short_name: x
				deny() { true }`)),
			expected: "a.b.c.x",
		},
		{
			name: "unknown category",
			annotation: annotationRef(heredoc.Doc(`
				package policy.something.a.b.c
				# METADATA
				# custom:
				#   short_name: x
				deny() { true }`)),
			expected: "something.a.b.c.x",
		},
		{
			name: "without just known category package",
			annotation: annotationRef(heredoc.Doc(`
				package release
				# METADATA
				# custom:
				#   short_name: x
				deny() { true }`)),
			expected: "x",
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, code(c.annotation))
		})
	}
}
