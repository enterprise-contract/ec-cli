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

func getCollections(a *ast.AnnotationsRef) []string {
	var collections []string
	if a.Annotations == nil || a.Annotations.Custom == nil {
		return collections
	}

	if interfaces, ok := a.Annotations.Custom["collections"].([]interface{}); ok {
		for _, maybeCollection := range interfaces {
			if collection, ok := maybeCollection.(string); ok {
				collections = append(collections, collection)
			}
		}
	}

	return collections
}

type TemplateFields = struct {
	TrimmedPath string
	ShortPath   string
	WarnDeny    string
	Title       string
	Description string
	ShortName   string
	DocsUrl     string
	Collections []string
}

var templates = map[string]string{
	"text": hd.Doc(`
		{{ .TrimmedPath }}.{{ .ShortName }} ({{ .WarnDeny }})
		{{ with .DocsUrl }}{{ . }}
		{{ end }}{{ .Title }}
		{{ .Description }}{{ if .Collections }}
		{{ .Collections }}{{ end }}
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
func PrepTemplateFields(a *ast.AnnotationsRef) TemplateFields {
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

	shortName := getShortName(a)
	collections := getCollections(a)

	// Notes:
	// - This makes the assumption that we're looking at our own EC rules with
	//   docs in the hacbs-contract github pages. That's not likely to be true
	//   always. A future improvement for this might include a way to extract a
	//   docs url from a package annotation instead using the hard-coded url here.
	// - The length test is because we're expecting pathStrings to be like this:
	//     data.policy.release.some_package_name.deny
	//   Avoid errors indexing pathStrings and also try to avoid showing a url
	//   if it's unlikely to be a real link to existing docs.
	var docsUrl string
	if len(pathStrings) == 5 && pathStrings[1] == "policy" && shortName != "" {
		docsUrl = fmt.Sprintf("https://hacbs-contract.github.io/ec-policies/%s_policy.html#%s__%s", pathStrings[2], pathStrings[3], shortName)
	}

	return TemplateFields{
		TrimmedPath: trimmedPath,
		ShortPath:   shortPath,
		WarnDeny:    pathStrings[len(pathStrings)-1],
		Title:       a.Annotations.Title,
		Description: a.Annotations.Description,
		ShortName:   shortName,
		DocsUrl:     docsUrl,
		Collections: collections,
	}
}

// Render using a template
func renderAnn(out io.Writer, a *ast.AnnotationsRef, tmplName string) error {
	t := template.Must(template.New("t").Parse(templates[tmplName]))
	return t.Execute(out, PrepTemplateFields(a))
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
