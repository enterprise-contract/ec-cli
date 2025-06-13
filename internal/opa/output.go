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

package opa

import (
	"embed"
	"fmt"
	"io"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"golang.org/x/exp/slices"

	"github.com/conforma/cli/internal/opa/rule"
	"github.com/conforma/cli/internal/utils"
)

//go:embed templates/*.tmpl
var efs embed.FS

// Render using a template
func renderAnn(out io.Writer, a *ast.AnnotationsRef, tmplName string) error {
	t, err := utils.SetupTemplate(efs)
	if err != nil {
		return err
	}
	return t.ExecuteTemplate(out, fmt.Sprintf("%s.tmpl", tmplName), rule.RuleInfo(a))
}

// Todo:
// - Group by package or collection
// - Filtering by package or collection maybe
// - More useful formats
func OutputText(out io.Writer, allData map[string][]*ast.AnnotationsRef, template string) error {
	sources := make([]string, 0, len(allData))
	for src := range allData {
		i, _ := slices.BinarySearch(sources, src)
		sources = slices.Insert(sources, i, src)
	}
	for _, src := range sources {
		annRefs := allData[src]
		if template == "text" {
			// This part could be templated too I guess but let's keep it simple for now
			fmt.Fprintf(out, "# Source: %s\n\n", src)
		}
		for _, ann := range annRefs {
			pathStrings := strings.Split(ann.Path.String(), ".")
			if ann.Annotations != nil {
				if string(ann.Annotations.Scope) == "rule" {
					err := renderAnn(out, ann, template)
					if err != nil {
						return err
					}
				}
				// Skip package annotations for now
			} else {
				// Handle edge case where there's no annotations at all
				fmt.Fprintf(out, "%s\n%s\n--\n",
					strings.Join(pathStrings[1:], "."),
					"(No annotations found)")
			}
		}
	}
	return nil
}
