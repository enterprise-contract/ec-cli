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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package definition

import (
	"encoding/json"
	"fmt"

	"github.com/ghodss/yaml"
	cOutput "github.com/open-policy-agent/conftest/output"

	"github.com/hacbs-contract/ec-cli/internal/format"
	"github.com/hacbs-contract/ec-cli/internal/output"
)

type ReportItem struct {
	Filename   string           `json:"filename"`
	Violations []cOutput.Result `json:"violations"`
	Warnings   []cOutput.Result `json:"warnings"`
	Success    bool             `json:"success"`
	Namespace  string           `json:"namespace"`
}

type ReportFormat string

const (
	JSONReport string = "json"
	YAMLReport string = "yaml"
)

type Report struct {
	items []ReportItem
}

func (r *Report) Add(o output.Output) {
	// adding the filename, failures and warnings to report
	for _, check := range o.PolicyCheck {
		item := ReportItem{
			Namespace:  check.Namespace,
			Filename:   check.FileName,
			Violations: check.Failures,
			Warnings:   check.Warnings,
			Success:    len(check.Failures) == 0,
		}

		r.items = append(r.items, item)
	}
}

func (r *Report) Write(targetName string, p format.TargetParser) error {
	if len(r.items) == 0 {
		return nil
	}

	var data []byte
	var err error

	target := p.Parse(targetName)

	switch target.Format {
	case JSONReport:
		if data, err = json.Marshal(r.items); err != nil {
			return err
		}
	case YAMLReport:
		if data, err = yaml.Marshal(r.items); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unexpected report format: %s", target.Format)
	}

	_, err = target.Write(data)
	return err
}
