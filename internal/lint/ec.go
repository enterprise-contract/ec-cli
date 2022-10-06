// Copyright 2022 Red Hat, Inc.
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

// Custom ec-cli linters get implemented here
package main

import (
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/multichecker"
)

type ecPlugin struct{}

// GetAnalyzers returns the private linters implemented in this package. That is
// the interfice required for custom golangci-linters, but due to an issue with
// applying the suggestions (fixes) we can't use it in that capacity. It remains
// here as we still can use it from the main function below.
func (*ecPlugin) GetAnalyzers() []*analysis.Analyzer {
	return []*analysis.Analyzer{
		&current,
		&returns,
	}
}

// AnalyzerPlugin is the entrypoint for custom linters in golangci-lint, we're
// not currently using this as a custom linter due to an issue described above
// and below. We keep it here as it might be used in the future and we do use it
// below in the main function.
var AnalyzerPlugin ecPlugin

// main runs the internal linters. Due to golangci-lint not supporting fixes
// (suggestions) via custom plugins we need to run this as a separate linter. If
// https://github.com/golangci/golangci-lint/issues/1779 gets resolved we can
// build without the main function here as a shared library (plugin) and include
// it in golangci-lint's configuration. See
// https://golangci-lint.run/contributing/new-linters/#how-to-add-a-private-linter-to-golangci-lint
func main() {
	multichecker.Main(AnalyzerPlugin.GetAnalyzers()...)
}
