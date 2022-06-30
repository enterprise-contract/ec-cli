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

package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/open-policy-agent/conftest/output"
)

// VerificationStatus represents the status and message of pass / fail
type VerificationStatus struct {
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

// addToViolations appends v.Message to the violations array provided
func (v VerificationStatus) addToViolations(violations []string) []string {
	if v.Passed {
		return violations
	}

	return append(violations, v.Message)
}

// Output is a struct representing checks and exit code.
type Output struct {
	ImageSignatureCheck       VerificationStatus   `json:"imageSignatureCheck"`
	AttestationSignatureCheck VerificationStatus   `json:"attestationSignatureCheck"`
	PolicyCheck               []output.CheckResult `json:"policyCheck"`
	ExitCode                  int                  `json:"-"`
}

// SetImageSignatureCheck sets the passed and message fields of the ImageSignatureCheck to the given values.
func (o *Output) SetImageSignatureCheck(passed bool, message string) {
	o.ImageSignatureCheck.Passed = passed
	o.ImageSignatureCheck.Message = message
}

// SetAttestationSignatureCheck sets the passed and message fields of the AttestationSignatureCheck to the given values.
func (o *Output) SetAttestationSignatureCheck(passed bool, message string) {
	o.AttestationSignatureCheck.Passed = passed
	o.AttestationSignatureCheck.Message = message
}

// SetPolicyCheck sets the PolicyCheck and ExitCode to the results and exit code of the Results
func (o *Output) SetPolicyCheck(results []output.CheckResult) {
	for r := range results {
		if results[r].FileName == "-" {
			results[r].FileName = ""
		}

		results[r].Queries = nil
	}
	o.PolicyCheck = results
	o.ExitCode = output.ExitCode(results)
}

// addCheckResultToViolations appends the failures from a given output.CheckResult to the violations array
func addCheckResultToViolations(c output.CheckResult, violations []string) []string {
	for _, failure := range c.Failures {
		violations = append(violations, failure.Message)
	}

	return violations
}

// addCheckResultsToViolations calls addCheckResultToViolation for each output.CheckResult in the given array and add it's
// failures to the violations array
func addCheckResultsToViolations(c []output.CheckResult, violations []string) []string {
	for _, check := range c {
		violations = addCheckResultToViolations(check, violations)
	}

	return violations
}

// Violations returns an array of violations
func (o Output) Violations() []string {
	violations := make([]string, 0, 10)
	violations = o.ImageSignatureCheck.addToViolations(violations)
	violations = o.AttestationSignatureCheck.addToViolations(violations)
	violations = addCheckResultsToViolations(o.PolicyCheck, violations)

	return violations
}

// Print prints an Output instance
func (o *Output) Print(out io.Writer) error {
	return o.print(out, "")
}

func (o *Output) print(out io.Writer, indent string) error {
	e := json.NewEncoder(out)
	e.SetIndent(indent, "\t")
	err := e.Encode(o)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	return nil
}

// Outputs is an array of Output
type Outputs []*Output

// Print prints an Outputs instance
func (o Outputs) Print(out io.Writer) error {
	fmt.Fprint(out, "[")
	first := true
	for _, output := range o {
		if first {
			fmt.Fprint(out, "\n\t")
		} else {
			fmt.Fprint(out, "\t,")
		}
		first = false
		err := output.print(out, "\t")
		if err != nil {
			return err
		}
	}
	fmt.Fprint(out, "]\n")
	return nil
}
