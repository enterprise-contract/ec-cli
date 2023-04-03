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

// Functions for inspecting rego code and annotations
package opa

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/spf13/afero"
)

func inspectSingle(path, module string) ([]*ast.AnnotationsRef, error) {
	mod, err := ast.ParseModuleWithOpts(path, module, ast.ParserOptions{
		ProcessAnnotation: true,
		JSONOptions: &ast.JSONOptions{
			MarshalOptions: ast.JSONMarshalOptions{
				IncludeLocation: ast.NodeToggle{
					AnnotationsRef: true,
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	as, errs := ast.BuildAnnotationSet([]*ast.Module{mod})
	if len(errs) > 0 {
		return nil, errors.New(errs.Error())
	}

	results := make([]*ast.AnnotationsRef, 0, len(mod.Rules))
	for _, rule := range mod.Rules {
		results = append(results, as.Chain(rule)...)
	}

	return results, nil
}

func inspectMultiple(paths, modules []string) ([]*ast.AnnotationsRef, error) {
	numPaths := len(paths)
	numModules := len(modules)
	if numPaths != numModules {
		return nil, fmt.Errorf("mismatched number of paths and modules: %d != %d", numPaths, numModules)
	}

	results := make([]*ast.AnnotationsRef, 0, numPaths)
	for i := 0; i < numPaths; i++ {
		r, err := inspectSingle(paths[i], modules[i])
		if err != nil {
			return nil, err
		}

		results = append(results, r...)
	}

	return results, nil
}

// Borrowed from conftest
func isWarning(ruleName string) bool {
	return regexp.MustCompile("^warn(_[a-zA-Z0-9]+)*$").MatchString(ruleName)
}

// Borrowed from conftest
func isFailure(ruleName string) bool {
	return regexp.MustCompile("^(deny|violation)(_[a-zA-Z0-9]+)*$").MatchString(ruleName)
}

func isWarnOrDeny(rule *ast.AnnotationsRef) bool {
	r := rule.GetRule()
	if r == nil {
		return false
	}
	ruleName := r.Head.Name.String()
	return isWarning(ruleName) || isFailure(ruleName)
}

func hasAnnotations(rule *ast.AnnotationsRef) bool {
	return rule.Annotations != nil
}

// Interesting rules are warns, denies, and anything with an annotation,
// which includes some package scoped annotations not assocated with a rule
func interestingRulesOnly(results []*ast.AnnotationsRef) ([]*ast.AnnotationsRef, error) {
	filteredResults := make([]*ast.AnnotationsRef, 0, len(results))
	for _, rule := range results {
		if isWarnOrDeny(rule) || hasAnnotations(rule) {
			filteredResults = append(filteredResults, rule)
		}
	}
	return filteredResults, nil
}

// destDir is usually something like /tmp/ec-workdir-1234/policy/f33dbeef so let's trim it
func shortPath(fullPath string, destDir string) string {
	return strings.TrimPrefix(strings.TrimPrefix(fullPath, destDir), "/")
}

// Finds all the rego files, inspects each one and returns a list the inspect data
func InspectDir(afs afero.Fs, dir string) ([]*ast.AnnotationsRef, error) {
	regoPaths := []string{}
	regoContents := []string{}

	// Find all the rego files
	err := afero.Walk(afs, dir, func(path string, d fs.FileInfo, readErr error) error {
		if readErr != nil {
			return readErr
		}

		if d.IsDir() {
			return nil
		}

		if strings.ToLower(filepath.Ext(path)) != ".rego" {
			return nil
		}

		// Prune out the tests early on
		if strings.HasSuffix(filepath.Base(path), "_test.rego") {
			return nil
		}

		contents, err := afero.ReadFile(afs, path)
		if err != nil {
			return nil
		}

		regoPaths = append(regoPaths, shortPath(path, dir))
		regoContents = append(regoContents, string(contents))
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Inspect all rego files found
	allAnnotations, err := inspectMultiple(regoPaths, regoContents)
	if err != nil {
		return nil, err
	}

	// Return only interesting rules
	result, err := interestingRulesOnly(allAnnotations)
	if err != nil {
		return nil, err
	}

	return result, nil
}
