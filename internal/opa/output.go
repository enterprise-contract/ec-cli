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

package opa

import (
	"fmt"
	"io"
	"strings"
	"text/template"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/open-policy-agent/opa/ast"

	"github.com/hacbs-contract/ec-cli/internal/opa/rule"
)

var templates = map[string]string{
	"text": hd.Doc(`
		{{ .Package }}.{{ .ShortName }} ({{ .Kind }})
		{{ with .DocumentationUrl }}{{ . }}
		{{ end }}{{ .Title }}
		{{ .Description }}{{ if .Collections }}
		{{ .Collections }}{{ end }}
		--
	`),

	"names": hd.Doc(`
		{{ .Package }}.{{ .ShortName }}
	`),

	"short-names": hd.Doc(`
		{{ .Code }}
	`),
}

// Render using a template
func renderAnn(out io.Writer, a *ast.AnnotationsRef, tmplName string) error {
	t := template.Must(template.New("t").Parse(templates[tmplName]))
	return t.Execute(out, rule.RuleInfo(a))
}

// Todo:
// - Group by package or collection
// - Filtering by package or collection maybe
// - More useful formats
func OutputText(out io.Writer, allData map[string][]*ast.AnnotationsRef, template string) error {
	for src, annRefs := range allData {
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
