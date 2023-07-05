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
	"encoding/xml"
	"fmt"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/hashicorp/go-multierror"
	conftestOutput "github.com/open-policy-agent/conftest/output"
	app "github.com/redhat-appstudio/application-api/api/v1alpha1"
	"sigs.k8s.io/yaml"

	"github.com/enterprise-contract/ec-cli/internal/format"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/signature"
	"github.com/enterprise-contract/ec-cli/internal/version"
)

type Component struct {
	app.SnapshotComponent
	Violations []conftestOutput.Result     `json:"violations,omitempty"`
	Warnings   []conftestOutput.Result     `json:"warnings,omitempty"`
	Successes  []conftestOutput.Result     `json:"successes,omitempty"`
	Success    bool                        `json:"success"`
	Signatures []signature.EntitySignature `json:"signatures,omitempty"`
}

type Report struct {
	Success       bool `json:"success"`
	created       time.Time
	Snapshot      string                           `json:"snapshot,omitempty"`
	Components    []Component                      `json:"components"`
	Key           string                           `json:"key"`
	Policy        ecc.EnterpriseContractPolicySpec `json:"policy"`
	EcVersion     string                           `json:"ec-version"`
	Data          any                              `json:"-"`
	EffectiveTime time.Time                        `json:"effective-time"`
}

type summary struct {
	Snapshot   string             `json:"snapshot,omitempty"`
	Components []componentSummary `json:"components"`
	Success    bool               `json:"success"`
	Key        string             `json:"key"`
}

type componentSummary struct {
	Name            string              `json:"name"`
	Success         bool                `json:"success"`
	Violations      map[string][]string `json:"violations"`
	Warnings        map[string][]string `json:"warnings"`
	Successes       map[string][]string `json:"successes"`
	TotalViolations int                 `json:"total_violations"`
	TotalWarnings   int                 `json:"total_warnings"`
	TotalSuccesses  int                 `json:"total_successes"`
}

// testReport represents the standardized TEST_OUTPUT format.
// The `Namespace` attribute is required for the appstudio results API. However,
// it is always an empty string from the ec-cli as a way to indicate all
// namespaces were used.
type testReport struct {
	Timestamp string `json:"timestamp"`
	Namespace string `json:"namespace"`
	Successes int    `json:"successes"`
	Failures  int    `json:"failures"`
	Warnings  int    `json:"warnings"`
	Result    string `json:"result"`
}

// Possible formats the report can be written as.
const (
	JSON      = "json"
	YAML      = "yaml"
	APPSTUDIO = "appstudio"
	// Deprecated. Remove when hacbs output is removed
	HACBS   = "hacbs"
	Summary = "summary"
	JUNIT   = "junit"
	DATA    = "data"
)

// WriteReport returns a new instance of Report representing the state of
// components from the snapshot.
func NewReport(snapshot string, components []Component, policy policy.Policy, data any) (Report, error) {
	success := true

	// Set the report success, remains true if all components are successful
	for _, component := range components {
		if !component.Success {
			success = false
			break
		}
	}

	key, err := policy.PublicKeyPEM()
	if err != nil {
		return Report{}, err
	}

	// TODO: Add some keyless information to the report.

	info, _ := version.ComputeInfo()

	return Report{
		Snapshot:      snapshot,
		Success:       success,
		Components:    components,
		created:       time.Now().UTC(),
		Key:           string(key),
		Policy:        policy.Spec(),
		EcVersion:     info.Version,
		Data:          data,
		EffectiveTime: policy.EffectiveTime().UTC(),
	}, nil
}

// WriteAll writes the report to all the given targets.
func (r Report) WriteAll(targets []string, p format.TargetParser) (allErrors error) {
	if len(targets) == 0 {
		targets = append(targets, JSON)
	}
	for _, targetName := range targets {
		target := p.Parse(targetName)

		if data, err := r.toFormat(target.Format); err != nil {
			allErrors = multierror.Append(allErrors, err)
		} else if _, err := target.Write(data); err != nil {
			allErrors = multierror.Append(allErrors, err)
		}
	}
	return
}

// toFormat converts the report into the given format.
func (r *Report) toFormat(format string) (data []byte, err error) {
	switch format {
	case JSON:
		data, err = json.Marshal(r)
	case YAML:
		data, err = yaml.Marshal(r)
	case Summary:
		data, err = json.Marshal(r.toSummary())
	case APPSTUDIO:
		data, err = json.Marshal(r.toAppstudioReport())
	// Deprecated. Remove when hacbs output is removed
	case HACBS:
		data, err = json.Marshal(r.toAppstudioReport())
	case JUNIT:
		data, err = xml.Marshal(r.toJUnit())
	case DATA:
		data, err = yaml.Marshal(r.Data)
	default:
		return nil, fmt.Errorf("%q is not a valid report format", format)
	}
	return
}

// toSummary returns a condensed version of the report.
func (r *Report) toSummary() summary {
	pr := summary{
		Snapshot: r.Snapshot,
	}
	for _, cmp := range r.Components {
		if !cmp.Success {
			pr.Success = false
		}
		c := componentSummary{
			TotalViolations: len(cmp.Violations),
			TotalWarnings:   len(cmp.Warnings),
			TotalSuccesses:  len(cmp.Successes),
			Success:         cmp.Success,
			Name:            cmp.Name,
			Violations:      condensedMsg(cmp.Violations),
			Warnings:        condensedMsg(cmp.Warnings),
			Successes:       condensedMsg(cmp.Successes),
		}
		pr.Components = append(pr.Components, c)
	}
	pr.Key = r.Key
	return pr
}

// condensedMsg reduces repetitive error messages.
func condensedMsg(results []conftestOutput.Result) map[string][]string {
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

// toAppstudioReport returns a version of the report that conforms to the
// TEST_OUTPUT format.
// (Note: the name of the Tekton task result where this generally
// gets written is now TEST_OUTPUT instead of TEST_OUTPUT)
func (r *Report) toAppstudioReport() testReport {
	result := testReport{Timestamp: fmt.Sprint(r.created.UTC().Unix())}

	hasFailures := false
	for _, component := range r.Components {
		result.Failures += len(component.Violations)
		result.Warnings += len(component.Warnings)
		if component.Success {
			result.Successes += 1
		} else {
			// It is possible, although quite unusual, that a component has no
			// listed violations but is still marked as not successful.
			hasFailures = true
		}
	}

	switch {
	case result.Failures > 0 || hasFailures:
		result.Result = "FAILURE"
	case result.Warnings > 0:
		result.Result = "WARNING"
	case result.Successes == 0:
		result.Result = "SKIPPED"
	default:
		result.Result = "SUCCESS"
	}

	return result
}
