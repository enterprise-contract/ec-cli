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
)

func getShortName(a *ast.AnnotationsRef) string {
	if a.Annotations == nil || a.Annotations.Custom == nil {
		return ""
	}

	str, ok := a.Annotations.Custom["short_name"].(string)

	if !ok {
		return ""
	}

	return str // yay
}

type TemplateFields = struct {
	TrimmedPath string
	WarnDeny    string
	Title       string
	Description string
	ShortName   string
}

var templates = map[string]string{
	"plain": hd.Doc(`
		{{ .TrimmedPath }}.{{ .ShortName }} ({{ .WarnDeny }})
		{{ .Title }}
		{{ .Description }}
		--
	`),
}

// Prepare data for use in the template
func prepTemplateFields(a *ast.AnnotationsRef) TemplateFields {
	pathStrings := strings.Split(a.Path.String(), ".")
	return TemplateFields{
		TrimmedPath: strings.Join(pathStrings[1:len(pathStrings)-1], "."),
		WarnDeny:    pathStrings[len(pathStrings)-1],
		Title:       a.Annotations.Title,
		Description: a.Annotations.Description,
		ShortName:   getShortName(a),
	}
}

// Render using a template
func renderAnn(out io.Writer, a *ast.AnnotationsRef, tmplName string) error {
	t := template.Must(template.New("t").Parse(templates[tmplName]))
	return t.Execute(out, prepTemplateFields(a))
}

// This output format is mostly placeholder/poc.
// Todo:
// - Group by source and package
// - Filtering, e.g by collection
// - Add different formats
// - Use templates
func OutputText(out io.Writer, allData map[string][]*ast.AnnotationsRef) error {
	for src, annRefs := range allData {
		fmt.Fprintf(out, "# Source: %s\n\n", src)
		for _, ann := range annRefs {
			pathStrings := strings.Split(ann.Path.String(), ".")
			if ann.Annotations != nil {
				if string(ann.Annotations.Scope) == "rule" {
					err := renderAnn(out, ann, "plain")
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
