// Copyright The Enterprise Contract Contributors
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

package utils

// Some wrappers for outputing text using a set of go templates
// stored as files in a directory and read in using go:embed.
// Includes a standard set of (hopefully) useful helper functions.

import (
	"bytes"
	"embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/mitchellh/go-wordwrap"
)

const (
	defaultMainTemplate = "main.tmpl"
	defaultGlob         = "*/*.tmpl"
)

func RenderFromTemplates(input any, efs embed.FS) ([]byte, error) {
	return RenderFromTemplatesWithMain(input, defaultMainTemplate, efs)
}

func RenderFromTemplatesWithMain(input any, main string, efs embed.FS) ([]byte, error) {
	return RenderFromTemplatesWithGlob(input, main, []string{defaultGlob}, efs)
}

func RenderFromTemplatesWithGlob(input any, main string, glob []string, efs embed.FS) ([]byte, error) {
	// Create blank template
	t := template.New("_")

	// Bring in helper functions
	t = t.Funcs(templateHelpers)

	// Bring in all the templates
	t, err := t.ParseFS(efs, glob...)
	if err != nil {
		return nil, err
	}

	// Render output
	var buf bytes.Buffer
	err = t.ExecuteTemplate(&buf, main, input)
	if err != nil {
		return nil, err
	}

	// Return result
	return buf.Bytes(), nil
}

// Helper funcs for use in templates

func passWarnFailChooser(color string, choices []string) string {
	switch strings.ToLower(color) {
	case "violation", "fail", "red":
		return choices[0]
	case "warning", "warn", "yellow":
		return choices[1]
	case "success", "pass", "green":
		return choices[2]
	default:
		return choices[3]
	}
}

func ansiColorText(code string, str string) string {
	if code == "" || !ColorEnabled {
		return str
	}
	return fmt.Sprintf("\x1b[%sm%s\x1b[0m", code, str)
}

// Surround text with ansi color codes
func colorText(color string, str string) string {
	code := passWarnFailChooser(color, []string{"31", "33", "32", ""})
	return ansiColorText(code, str)
}

// Return one char to indicate a fail/warn/pass
func indicator(color string) string {
	return passWarnFailChooser(color, []string{"✕", "›", "✓", "*"})
}

// Make it color also
func colorIndicator(color string) string {
	return colorText(color, indicator(color))
}

// Wrap text to a certain width
func wrap(width int, s string) string {
	return wordwrap.WrapString(s, uint(width))
}

// Indent with spaces and also wrap
func indentWrap(indent int, width int, s string) string {
	indentStr := strings.Repeat(" ", indent)
	return indentStr + strings.ReplaceAll(wrap(width-indent, s), "\n", "\n"+indentStr)
}

// A way to assemble a map from keys and values in a template
func toMap(values ...interface{}) (map[string]interface{}, error) {
	if len(values)%2 != 0 {
		return nil, fmt.Errorf("toMap called with an odd number of args")
	}
	m := make(map[string]interface{}, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, fmt.Errorf("toMap keys must be strings")
		}
		m[key] = values[i+1]
	}
	return m, nil
}

// For use in template.Funcs above
// Todo maybe: Use reflect to find the functions and make this dynamic
var templateHelpers = template.FuncMap{
	"colorText":      colorText,
	"indicator":      indicator,
	"colorIndicator": colorIndicator,
	"wrap":           wrap,
	"indentWrap":     indentWrap,
	"toMap":          toMap,
}
