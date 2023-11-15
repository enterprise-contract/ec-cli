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

package applicationsnapshot

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/hashicorp/go-multierror"
	app "github.com/redhat-appstudio/application-api/api/v1alpha1"
	"sigs.k8s.io/yaml"

	"github.com/enterprise-contract/ec-cli/internal/attestation"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/format"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/signature"
	"github.com/enterprise-contract/ec-cli/internal/version"
)

type Component struct {
	app.SnapshotComponent
	Violations   []evaluator.Result          `json:"violations,omitempty"`
	Warnings     []evaluator.Result          `json:"warnings,omitempty"`
	Successes    []evaluator.Result          `json:"successes,omitempty"`
	Success      bool                        `json:"success"`
	SuccessCount int                         `json:"-"`
	Signatures   []signature.EntitySignature `json:"signatures,omitempty"`
	Attestations []attestation.Attestation   `json:"attestations,omitempty"`
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
	PolicyInput   [][]byte                         `json:"-"`
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

// TestReport represents the standardized TEST_OUTPUT format.
// The `Namespace` attribute is required for the appstudio results API. However,
// it is always an empty string from the ec-cli as a way to indicate all
// namespaces were used.
type TestReport struct {
	Timestamp string `json:"timestamp"`
	Namespace string `json:"namespace"`
	Successes int    `json:"successes"`
	Failures  int    `json:"failures"`
	Warnings  int    `json:"warnings"`
	Result    string `json:"result"`
	Note      string `json:"note,omitempty"`
}

// Possible formats the report can be written as.
const (
	SummaryMarkdown = "summary-markdown"
	JSON            = "json"
	YAML            = "yaml"
	APPSTUDIO       = "appstudio"
	// Deprecated. Remove when hacbs output is removed
	HACBS       = "hacbs"
	Summary     = "summary"
	JUNIT       = "junit"
	DATA        = "data"
	ATTESTATION = "attestation"
	PolicyInput = "policy-input"
	VSA         = "vsa"
)

// WriteReport returns a new instance of Report representing the state of
// components from the snapshot.
func NewReport(snapshot string, components []Component, policy policy.Policy, data any, policyInput [][]byte) (Report, error) {
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
		PolicyInput:   policyInput,
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

		data, err := r.toFormat(target.Format)
		if err != nil {
			allErrors = multierror.Append(allErrors, err)
		}

		if !bytes.HasSuffix(data, []byte{'\n'}) {
			data = append(data, "\n"...)
		}

		if _, err := target.Write(data); err != nil {
			allErrors = multierror.Append(allErrors, err)
		}
	}
	return
}

// toFormat converts the report into the given format.
func (r *Report) toFormat(format string) (data []byte, err error) {
	switch format {
	case SummaryMarkdown:
		data, err = generateMarkdownSummary(r)
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
	case ATTESTATION:
		data, err = r.renderAttestations()
	case PolicyInput:
		data = bytes.Join(r.PolicyInput, []byte("\n"))
	case VSA:
		data, err = r.toVSA()
	default:
		return nil, fmt.Errorf("%q is not a valid report format", format)
	}
	return
}

func (r *Report) toVSA() ([]byte, error) {
	vsa, err := NewVSA(*r)
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(vsa)
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

			// Because cmp.Successes does not get populated unless the --show-successes
			// flag was set, cmp.SuccessCount is used here instead of len(cmp.Successes)
			TotalSuccesses: cmp.SuccessCount,

			Success:    cmp.Success,
			Name:       cmp.Name,
			Violations: condensedMsg(cmp.Violations),
			Warnings:   condensedMsg(cmp.Warnings),
			Successes:  condensedMsg(cmp.Successes),
		}
		pr.Components = append(pr.Components, c)
	}
	pr.Key = r.Key
	return pr
}

// condensedMsg reduces repetitive error messages.
func condensedMsg(results []evaluator.Result) map[string][]string {
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

func generateMarkdownSummary(r *Report) ([]byte, error) {
	var markdownBuffer bytes.Buffer
	markdownBuffer.WriteString("| Field     | Value |Status|\n")
	markdownBuffer.WriteString("|-----------|-------|-------|\n")

	var totalViolations, totalWarnings, totalSuccesses int
	pr := r.toSummary()
	for _, component := range pr.Components {
		totalViolations += component.TotalViolations
		totalWarnings += component.TotalWarnings
		totalSuccesses += component.TotalSuccesses
	}

	writeIcon := func(condition bool) string {
		if condition {
			return ":white_check_mark:"
		}
		return ":x:"
	}

	writeMarkdownField(&markdownBuffer, "Time", r.created.UTC().Format("2006-01-02 15:04:05"), "")
	writeMarkdownField(&markdownBuffer, "Successes", totalSuccesses, writeIcon(totalSuccesses >= 1 && totalViolations == 0))
	writeMarkdownField(&markdownBuffer, "Failures", totalViolations, writeIcon(totalViolations == 0))
	writeMarkdownField(&markdownBuffer, "Warnings", totalWarnings, writeIcon(totalWarnings == 0))
	writeMarkdownField(&markdownBuffer, "Result", "", writeIcon(r.Success))
	return markdownBuffer.Bytes(), nil
}

func writeMarkdownField(buffer *bytes.Buffer, name string, value any, icon string) {
	valueStr := fmt.Sprintf("%v", value)
	buffer.WriteString(fmt.Sprintf("| %s | %s | %s |\n", name, valueStr, icon))
}

// toAppstudioReport returns a version of the report that conforms to the
// TEST_OUTPUT format, usually written to the TEST_OUTPUT Tekton task result
func (r *Report) toAppstudioReport() TestReport {
	result := TestReport{
		Timestamp: fmt.Sprint(r.created.UTC().Unix()),
		// EC generally runs with the AllNamespaces flag set to true
		// and policies from many namespaces. Rather than try to list
		// them all in this string field we just leave it blank.
		Namespace: "",
	}

	hasFailures := false
	for _, component := range r.toSummary().Components {
		result.Failures += component.TotalViolations
		result.Warnings += component.TotalWarnings
		result.Successes += component.TotalSuccesses

		if !component.Success {
			// It is possible, although quite unusual, that a component has no
			// listed violations but is still marked as not successful.
			hasFailures = true
		}
	}

	result.DeriveResult(hasFailures)
	return result
}

func (r *TestReport) DeriveResult(hasFailures bool) {
	switch {
	case r.Failures > 0 || hasFailures:
		r.Result = "FAILURE"
	case r.Warnings > 0:
		r.Result = "WARNING"
	case r.Successes == 0:
		r.Result = "SKIPPED"
	default:
		r.Result = "SUCCESS"
	}
}

// It's redundant and perhaps not very useful, but let's produce some kind of
// a human readable note. We could perhaps make this more sophisticated in future,
// e.g. by including an abbreviated list of failure or warning messages.
func (r *TestReport) DeriveNote() {
	switch {
	case r.Result == "FAILURE":
		r.Note = "Failures detected"
	case r.Result == "WARNING":
		r.Note = "Warnings detected"
	case r.Result == "SKIPPED":
		r.Note = "All checks were skipped"
	case r.Result == "SUCCESS":
		r.Note = "All checks passed successfully"
	}
}

func OutputAppstudioReport(t TestReport) {
	out, err := json.Marshal(t)
	if err != nil {
		// Unlikely
		panic(err)
	}
	fmt.Printf("%s\n", out)
}

func AppstudioReportForError(prefix string, err error) TestReport {
	return TestReport{
		Timestamp: fmt.Sprint(time.Now().UTC().Unix()),
		Namespace: "",
		Successes: 0,
		Warnings:  0,
		Failures:  0,
		Result:    "ERROR",
		Note:      fmt.Sprintf("Error: %s: %s", prefix, err.Error()),
	}
}
