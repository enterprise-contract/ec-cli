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
	ShortPath   string
	WarnDeny    string
	Title       string
	Description string
	ShortName   string
}

var templates = map[string]string{
	"text": hd.Doc(`
		{{ .TrimmedPath }}.{{ .ShortName }} ({{ .WarnDeny }})
		{{ .Title }}
		{{ .Description }}
		--
	`),

	"names": hd.Doc(`
		{{ .TrimmedPath }}.{{ .ShortName }}
	`),

	"short-names": hd.Doc(`
		{{ .ShortPath }}.{{ .ShortName }}
	`),
}

// Prepare data for use in the template
func prepTemplateFields(a *ast.AnnotationsRef) TemplateFields {
	pathStrings := strings.Split(a.Path.String(), ".")

	// Removes the "data." prefix
	// Example: "policy.pipeline.required_tasks.missing_required_task"
	trimmedPath := strings.Join(pathStrings[1:len(pathStrings)-1], ".")

	var shortPath string
	if len(pathStrings) > 4 && strings.HasPrefix(trimmedPath, "policy.") {
		// Example "required_tasks.missing_required_task"
		shortPath = strings.Join(pathStrings[3:len(pathStrings)-1], ".")
	} else {
		// Edge case in case the package name doesn't follow our usual
		// conventions i.e. "package policy.<type>.<name>"
		shortPath = trimmedPath
	}
	return TemplateFields{
		TrimmedPath: trimmedPath,
		ShortPath:   shortPath,
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
