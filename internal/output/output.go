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
	"strings"

	"github.com/open-policy-agent/conftest/output"
	"github.com/sigstore/cosign/pkg/cosign"
	log "github.com/sirupsen/logrus"
)

const missingSignatureMessage = "No image signatures found matching the given public key. " +
	"Verify the correct public key was provided, " +
	"and a signature was created."

const missingAttestationMessage = "No image attestations found matching the given public key. " +
	"Verify the correct public key was provided, " +
	"and one or more attestations were created."

// VerificationStatus represents the status of a verification check.
type VerificationStatus struct {
	Passed bool           `json:"passed"`
	Result *output.Result `json:"result,omitempty"`
}

// addToViolations appends the failure result to the violations slice.
func (v VerificationStatus) addToViolations(violations []output.Result) []output.Result {
	if v.Passed {
		return violations
	}

	result := violations
	if v.Result != nil {
		result = append(violations, *v.Result)
	}

	return result
}

type EntitySignature struct {
	KeyID     string            `json:"keyid"`
	Signature string            `json:"sig"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Output is a struct representing checks and exit code.
type Output struct {
	ImageAccessibleCheck      VerificationStatus   `json:"imageAccessibleCheck"`
	ImageSignatureCheck       VerificationStatus   `json:"imageSignatureCheck"`
	AttestationSignatureCheck VerificationStatus   `json:"attestationSignatureCheck"`
	AttestationSyntaxCheck    VerificationStatus   `json:"attestationSyntaxCheck"`
	PolicyCheck               []output.CheckResult `json:"policyCheck"`
	ExitCode                  int                  `json:"-"`
	Signatures                []EntitySignature    `json:"signatures,omitempty"`
	ImageURL                  string               `json:"-"`
	Detailed                  bool                 `json:"-"`
}

// SetImageAccessibleCheck sets the passed and result.message fields of the ImageAccessibleCheck to the given values.
func (o *Output) SetImageAccessibleCheckFromError(err error) {
	if err == nil {
		log.Debug("Image access check passed")
		o.ImageAccessibleCheck.Passed = true
		return
	}

	log.Debugf("Image access check failed. Error: %s", err.Error())
	o.ImageAccessibleCheck.Passed = false
	message := fmt.Sprintf("Image URL is not accessible: %s", err)
	o.ImageAccessibleCheck.Result = &output.Result{Message: message}
}

// SetImageSignatureCheck sets the passed and result.message fields of the ImageSignatureCheck to the given values.
func (o *Output) SetImageSignatureCheckFromError(err error) {
	if err == nil {
		log.Debug("Image signature check passed")
		o.ImageSignatureCheck.Passed = true
		return
	}

	log.Debug("Image signature check failed")
	o.ImageSignatureCheck.Passed = false

	var message string
	if strings.HasPrefix(err.Error(), cosign.ErrNoMatchingSignatures.Error()) {
		// If the error is due to no matching signatures, use a more user-friendly message.
		message = missingSignatureMessage
	} else {
		message = fmt.Sprintf("Image signature check failed: %s", err)
	}

	o.ImageSignatureCheck.Result = &output.Result{Message: message}
}

// SetAttestationSignatureCheck sets the passed and result.message fields of the AttestationSignatureCheck to the given values.
func (o *Output) SetAttestationSignatureCheckFromError(err error) {
	if err == nil {
		log.Debug("Image signature check passed")
		o.AttestationSignatureCheck.Passed = true
		return
	}

	log.Debug("Image attestation signature check failed")
	o.AttestationSignatureCheck.Passed = false

	var message string
	if strings.HasPrefix(err.Error(), cosign.ErrNoMatchingAttestations.Error()) {
		// If the error is due to no matching attestations, use a more user-friendly message.
		message = missingAttestationMessage
	} else {
		message = fmt.Sprintf("Image attestation check failed: %s", err.Error())
	}

	o.AttestationSignatureCheck.Result = &output.Result{Message: message}
}

// SetAttestationSyntaxCheck sets the passed and result.message fields of the AttestationSyntaxCheck to the given values.
func (o *Output) SetAttestationSyntaxCheckFromError(err error) {
	if err == nil {
		log.Debug("Image attestation syntax check passed")
		o.AttestationSyntaxCheck.Passed = true
		return
	}

	o.AttestationSyntaxCheck.Passed = false
	message := fmt.Sprintf("Attestation syntax check failed: %s", err)
	o.AttestationSyntaxCheck.Result = &output.Result{Message: message}
}

// SetPolicyCheck sets the PolicyCheck and ExitCode to the results and exit code of the Results
func (o *Output) SetPolicyCheck(results []output.CheckResult) {
	for r := range results {
		if results[r].FileName == "-" {
			results[r].FileName = ""
		}

		results[r].Queries = nil

		if !o.Detailed {
			keepSomeMetadata(results[r].Exceptions)
			keepSomeMetadata(results[r].Failures)
			keepSomeMetadata(results[r].Skipped)
			keepSomeMetadata(results[r].Warnings)
		}
	}
	o.PolicyCheck = results
	o.ExitCode = output.ExitCode(results)
}

func keepSomeMetadata(results []output.Result) {
	for i := range results {
		for key := range results[i].Metadata {
			if key == "code" || key == "effective_on" {
				continue
			}

			delete(results[i].Metadata, key)
		}
	}
}

// addCheckResultsToViolations appends the Failures from CheckResult to the violations slice.
func (o Output) addCheckResultsToViolations(violations []output.Result) []output.Result {
	for _, check := range o.PolicyCheck {
		violations = append(violations, check.Failures...)
	}

	return violations
}

// Violations aggregates and returns all violations.
func (o Output) Violations() []output.Result {
	violations := make([]output.Result, 0, 10)
	violations = o.ImageSignatureCheck.addToViolations(violations)
	violations = o.ImageAccessibleCheck.addToViolations(violations)
	violations = o.AttestationSignatureCheck.addToViolations(violations)
	violations = o.AttestationSyntaxCheck.addToViolations(violations)
	violations = o.addCheckResultsToViolations(violations)

	return violations
}

// Warnings aggregates and returns all warnings.
func (o Output) Warnings() []output.Result {
	warnings := make([]output.Result, 0, 10)
	for _, result := range o.PolicyCheck {
		warnings = append(warnings, result.Warnings...)
	}
	return warnings
}

func (o Output) SuccessCount() int {
	var passes int
	for _, result := range o.PolicyCheck {
		passes += result.Successes

	}
	return passes
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
