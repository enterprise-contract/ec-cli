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
	"sort"

	"github.com/open-policy-agent/conftest/output"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	log "github.com/sirupsen/logrus"

	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/signature"
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

// addToSuccesses appends the success result to the successes slice.
func (v VerificationStatus) addToSuccesses(successes []output.Result) []output.Result {
	if !v.Passed {
		return successes
	}

	result := successes
	if v.Result != nil {
		result = append(successes, *v.Result)
	}

	return result
}

type Attestation struct {
	Type               string                      `json:"type"`
	PredicateType      string                      `json:"predicateType"`
	PredicateBuildType string                      `json:"predicateBuildType,omitempty"`
	Signatures         []signature.EntitySignature `json:"signatures"`
}

// Output is a struct representing checks and exit code.
type Output struct {
	ImageAccessibleCheck      VerificationStatus          `json:"imageAccessibleCheck"`
	ImageSignatureCheck       VerificationStatus          `json:"imageSignatureCheck"`
	AttestationSignatureCheck VerificationStatus          `json:"attestationSignatureCheck"`
	AttestationSyntaxCheck    VerificationStatus          `json:"attestationSyntaxCheck"`
	PolicyCheck               evaluator.CheckResults      `json:"policyCheck"`
	ExitCode                  int                         `json:"-"`
	Signatures                []signature.EntitySignature `json:"signatures,omitempty"`
	Attestations              []Attestation               `json:"attestations,omitempty"`
	ImageURL                  string                      `json:"-"`
	Detailed                  bool                        `json:"-"`
	Data                      []evaluator.Data            `json:"-"`
	Policy                    policy.Policy               `json:"-"`
}

// SetImageAccessibleCheck sets the passed and result.message fields of the ImageAccessibleCheck to the given values.
func (o *Output) SetImageAccessibleCheckFromError(err error) {
	metadata := map[string]interface{}{
		"code":  "builtin.image.accessible",
		"title": "Image URL is accessible",
	}
	var message string
	if err == nil {
		o.ImageAccessibleCheck.Passed = true
		message = "Pass"
		log.Debug("Image URL is accessible")
	} else {
		o.ImageAccessibleCheck.Passed = false
		message = fmt.Sprintf("Image URL is not accessible: %s", err)
		log.Debugf("%s. Error: %s", message, err.Error())
	}
	result := &output.Result{Message: message, Metadata: metadata}
	if !o.Detailed {
		keepSomeMetadataSingle(*result)
	}
	o.ImageAccessibleCheck.Result = result
}

// SetImageSignatureCheck sets the passed and result.message fields of the ImageSignatureCheck to the given values.
func (o *Output) SetImageSignatureCheckFromError(err error) {
	metadata := map[string]interface{}{
		"code":  "builtin.image.signature_check",
		"title": "Image signature check passed",
	}
	var message string

	if err == nil {
		o.ImageSignatureCheck.Passed = true
		message = "Pass"
		log.Debug("Image signature check passed")
	} else {
		o.ImageSignatureCheck.Passed = false
		message = wrapCosignErrorMessage(err, "signature", o.Policy)
		log.Debug(message)
	}
	result := &output.Result{Message: message, Metadata: metadata}
	if !o.Detailed {
		keepSomeMetadataSingle(*result)
	}
	o.ImageSignatureCheck.Result = result
}

// SetAttestationSignatureCheck sets the passed and result.message fields of the AttestationSignatureCheck to the given values.
func (o *Output) SetAttestationSignatureCheckFromError(err error) {
	metadata := map[string]interface{}{
		"code":  "builtin.attestation.signature_check",
		"title": "Attestation signature check passed",
	}
	var message string

	if err == nil {
		o.AttestationSignatureCheck.Passed = true
		message = "Pass"
		log.Debug("Attestation signature check passed")
	} else {
		o.AttestationSignatureCheck.Passed = false
		message = wrapCosignErrorMessage(err, "attestation", o.Policy)
		log.Debug(message)
	}
	result := &output.Result{Message: message, Metadata: metadata}
	if !o.Detailed {
		keepSomeMetadataSingle(*result)
	}
	o.AttestationSignatureCheck.Result = result
}

// SetAttestationSyntaxCheck sets the passed and result.message fields of the AttestationSyntaxCheck to the given values.
func (o *Output) SetAttestationSyntaxCheckFromError(err error) {
	metadata := map[string]interface{}{
		"code":  "builtin.attestation.syntax_check",
		"title": "Attestation syntax check passed",
	}
	var message string

	if err == nil {
		o.AttestationSyntaxCheck.Passed = true
		message = "Pass"
		log.Debug("Attestation syntax check passed")
	} else {
		o.AttestationSyntaxCheck.Passed = false
		message = fmt.Sprintf("Attestation syntax check failed: %s", err)
		log.Debug(message)
	}
	result := &output.Result{Message: message, Metadata: metadata}
	if !o.Detailed {
		keepSomeMetadataSingle(*result)
	}
	o.AttestationSyntaxCheck.Result = result
}

// SetPolicyCheck sets the PolicyCheck and ExitCode to the results and exit code of the Results
func (o *Output) SetPolicyCheck(results evaluator.CheckResults) {
	for r := range results {
		if results[r].FileName == "-" {
			results[r].FileName = ""
		}

		results[r].Queries = nil

		if !o.Detailed {
			keepSomeMetadata(results[r].Exceptions)
			keepSomeMetadata(results[r].Failures)
			keepSomeMetadata(results[r].Successes)
			keepSomeMetadata(results[r].Skipped)
			keepSomeMetadata(results[r].Warnings)
		}
	}
	o.PolicyCheck = results
	o.ExitCode = output.ExitCode(results.ToConftestResults())
}

func keepSomeMetadata(results []output.Result) {
	for i := range results {
		keepSomeMetadataSingle(results[i])
	}
}

func keepSomeMetadataSingle(result output.Result) {
	for key := range result.Metadata {
		if key == "code" || key == "effective_on" {
			continue
		}
		delete(result.Metadata, key)
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

	violations = sortResults(violations)
	return violations
}

// Warnings aggregates and returns all warnings.
func (o Output) Warnings() []output.Result {
	warnings := make([]output.Result, 0, 10)
	for _, result := range o.PolicyCheck {
		warnings = append(warnings, result.Warnings...)
	}

	warnings = sortResults(warnings)
	return warnings
}

// Successes aggregates and returns all successes.
func (o Output) Successes() []output.Result {
	successes := make([]output.Result, 0, 10)
	for _, result := range o.PolicyCheck {
		successes = append(successes, result.Successes...)
	}

	successes = o.ImageSignatureCheck.addToSuccesses(successes)
	successes = o.AttestationSignatureCheck.addToSuccesses(successes)
	successes = o.AttestationSyntaxCheck.addToSuccesses(successes)

	successes = sortResults(successes)
	return successes
}

// sortResults sorts Result slices.
func sortResults(results []output.Result) []output.Result {
	sort.Slice(results, func(i, j int) bool {
		iCode := evaluator.ExtractStringFromMetadata(results[i], "code")
		jCode := evaluator.ExtractStringFromMetadata(results[j], "code")
		if iCode == jCode {
			iTerm := evaluator.ExtractStringFromMetadata(results[i], "term")
			jTerm := evaluator.ExtractStringFromMetadata(results[j], "term")
			if iTerm == jTerm {
				return results[i].Message < results[j].Message
			}
			return iTerm < jTerm
		}
		return iCode < jCode
	})
	return results
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

// wrapCosignErrorMessage wraps the message from the given error indicating the
// type of check that was performed. It may also completey change the  message
// with a more helpful one in some cases.
func wrapCosignErrorMessage(err error, checkType string, p policy.Policy) string {
	// When NOT using the keyless workflow, the "no matching signatures" error from cosign lacks
	// any useful information. Only in such case, change the error message to something more
	// helpful.
	if p == nil || !p.Keyless() {
		var noMatchingErr string
		var msg string
		switch checkType {
		case "signature":
			noMatchingErr = cosign.ErrNoMatchingSignaturesType
			msg = missingSignatureMessage
		case "attestation":
			noMatchingErr = cosign.ErrNoMatchingAttestationsType
			msg = missingAttestationMessage
		}
		if vErr, ok := err.(*cosign.VerificationError); ok && vErr.ErrorType() == noMatchingErr && msg != "" {
			return msg
		}
	}
	return fmt.Sprintf("Image %s check failed: %s", checkType, err)
}
