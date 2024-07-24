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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package definition

import (
	"encoding/json"
	"fmt"

	"sigs.k8s.io/yaml"

	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/format"
	"github.com/enterprise-contract/ec-cli/internal/output"
	"github.com/enterprise-contract/ec-cli/internal/version"
)

type ReportItem struct {
	Filename   string             `json:"filename"`
	Violations []evaluator.Result `json:"violations"`
	Warnings   []evaluator.Result `json:"warnings"`
	Successes  []evaluator.Result `json:"successes"`
}

type ReportFormat string

const (
	JSONReport string = "json"
	YAMLReport string = "yaml"
)

type Report struct {
	Definitions []ReportItem `json:"definitions"`
	Success     bool         `json:"success"`
	EcVersion   string       `json:"ec-version"`
}

func NewReport() Report {
	info, _ := version.ComputeInfo()
	return Report{
		Success:   true,
		EcVersion: info.Version,
	}
}

func (r *Report) Add(o output.Output) {
	// group the results by filename. If multiple files are passed
	// to the testRunner, conftest evaluates all files against each namespace.
	itemsByFile := make(map[string]ReportItem)

	// check contains results from each namespace evaluated per definition
	for _, check := range o.PolicyCheck {
		if _, ok := itemsByFile[check.FileName]; !ok {
			itemsByFile[check.FileName] = ReportItem{
				Violations: []evaluator.Result{},
				Warnings:   []evaluator.Result{},
				Successes:  []evaluator.Result{},
			}
		}
		item := itemsByFile[check.FileName]
		item.Violations = append(item.Violations, check.Failures...)
		item.Warnings = append(item.Warnings, check.Warnings...)
		item.Successes = append(item.Successes, check.Successes...)
		item.Filename = check.FileName
		itemsByFile[check.FileName] = item
	}

	for _, value := range itemsByFile {
		if len(value.Violations) > 0 {
			// set Report.Success to false if any violations
			r.Success = false
		}
		r.Definitions = append(r.Definitions, value)
	}
}

func (r *Report) Write(targetName string, p format.TargetParser) error {
	if len(r.Definitions) == 0 {
		return nil
	}

	target, err := p.Parse(targetName)
	if err != nil {
		return err
	}

	var data []byte
	switch target.Format {
	case JSONReport:
		if data, err = json.Marshal(r); err != nil {
			return err
		}
	case YAMLReport:
		if data, err = yaml.Marshal(r); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unexpected report format: %s", target.Format)
	}

	_, err = target.Write(data)
	return err
}
