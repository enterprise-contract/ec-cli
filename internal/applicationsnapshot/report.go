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

package applicationsnapshot

import (
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/conftest/output"
	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
)

type Component struct {
	appstudioshared.ApplicationSnapshotComponent
	Violations []output.Result `json:"violations"`
	Warnings   []output.Result `json:"warnings"`
	Success    bool            `json:"success"`
}

type report struct {
	Success    bool        `json:"success"`
	Components []Component `json:"components"`
}

type summary struct {
	Components []componentSummary `json:"components"`
	Success    bool               `json:"success"`
}

type componentSummary struct {
	Name            string              `json:"name"`
	Success         bool                `json:"success"`
	Violations      map[string][]string `json:"violations"`
	Warnings        map[string][]string `json:"warnings"`
	TotalViolations int                 `json:"total_violations"`
	TotalWarnings   int                 `json:"total_warnings"`
}

func NewReport(components []Component, reportSummary bool) (string, error, bool) {
	var j []byte
	var err error

	report := Report(components)
	success := report.Success

	if reportSummary {
		j, err = json.Marshal(report.reportSummary())
	} else {
		j, err = json.Marshal(report)
	}

	if err != nil {
		return "", err, false
	}

	return string(j), nil, success
}

// Report the states of components from the snapshot
func Report(components []Component) report {
	success := true

	// Set the report success, remains true if all components are successful
	for _, component := range components {
		if !component.Success {
			success = false
			break
		}
	}

	output := report{
		Success:    success,
		Components: components,
	}
	return output
}

// a report with condensed error messaging
func (r *report) reportSummary() summary {
	var pr summary
	for _, cmp := range r.Components {
		if !cmp.Success {
			pr.Success = false
		}
		c := componentSummary{
			TotalViolations: len(cmp.Violations),
			TotalWarnings:   len(cmp.Warnings),
			Success:         cmp.Success,
			Name:            cmp.Name,
			Violations:      condensedMsg(cmp.Violations),
			Warnings:        condensedMsg(cmp.Warnings),
		}
		pr.Components = append(pr.Components, c)
	}
	return pr
}

// condense the error messages
func condensedMsg(results []output.Result) map[string][]string {
	maxErr := 1
	shortNames := make(map[string][]string)
	count := make(map[string]int)
	for _, v := range results {
		code, isPresent := v.Metadata["code"]
		// we don't want to keep count of the empty string
		if isPresent {
			code := fmt.Sprintf("%v", code)
			if count[code] < maxErr {
				shortNames[code] = append(shortNames[code], v.Message)
			}
			count[code] = count[code] + 1
		}
	}
	for k := range shortNames {
		if count[k] > maxErr {
			shortNames[k] = append(shortNames[k], fmt.Sprintf("There are %v more %q messages", count[k]-1, k))
		}
	}
	return shortNames
}
