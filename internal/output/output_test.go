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

//go:build unit

package output

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/open-policy-agent/conftest/output"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/stretchr/testify/assert"
)

func Test_PrintExpectedJSON(t *testing.T) {
	output := Output{
		ImageSignatureCheck: VerificationStatus{
			Passed: true,
			Result: &output.Result{Message: "message1"},
		},
		ImageAccessibleCheck: VerificationStatus{
			Passed: true,
			Result: &output.Result{Message: "message2"},
		},
		AttestationSignatureCheck: VerificationStatus{
			Passed: false,
			Result: &output.Result{Message: "message3"},
		},
		AttestationSyntaxCheck: VerificationStatus{
			Passed: false,
			Result: &output.Result{Message: "message4"},
		},
		PolicyCheck: []output.CheckResult{
			{
				FileName:  "file1.json",
				Namespace: "namespace1",
				Successes: 123,
				Skipped: []output.Result{
					{Message: "result11"},
					{Message: "result12"},
				},
				Warnings: []output.Result{
					{Message: "result13"},
					{Message: "result14"},
				},
				Failures: []output.Result{
					{Message: "result15"},
				},
				Exceptions: []output.Result{},
			},
			{
				FileName:  "file2.json",
				Namespace: "namespace2",
				Successes: 321,
				Skipped: []output.Result{
					{
						Message: "result21",
					},
				},
			},
		},
		Signatures: []EntitySignature{
			{KeyID: "key-id", Signature: "signature"},
		},
		ExitCode: 42,
	}

	var json bytes.Buffer
	output.Print(&json)

	assert.JSONEq(t, `{
		"imageSignatureCheck": {
		  "passed": true,
		  "result": {
		    "msg": "message1"
		  }
		},
		"imageAccessibleCheck": {
		  "passed": true,
		  "result": {
		    "msg": "message2"
		  }
		},
		"attestationSignatureCheck": {
		  "passed": false,
		  "result": {
		    "msg": "message3"
		  }
		},
		"attestationSyntaxCheck": {
			"passed": false,
			"result": {
			  "msg": "message4"
			}
		  },
		"policyCheck": [
		  {
			"filename": "file1.json",
			"namespace": "namespace1",
			"successes": 123,
			"skipped": [
			  {
				"msg": "result11"
			  },
			  {
				"msg": "result12"
			  }
			],
			"warnings": [
			  {
				"msg": "result13"
			  },
			  {
				"msg": "result14"
			  }
			],
			"failures": [
			  {
				"msg": "result15"
			  }
			]
		  },
		  {
			"filename": "file2.json",
			"namespace": "namespace2",
			"successes": 321,
			"skipped": [
			  {
				"msg": "result21"
			  }
			]
		  }
		],
		"signatures": [{"keyid": "key-id", "sig": "signature"}]
	  }`, json.String())
}

func Test_PrintOutputsExpectedJSON(t *testing.T) {
	// we don't care much about content as much as the JSON encoding is correct
	outputs := Outputs{
		{},
		{},
	}

	var buff bytes.Buffer

	outputs.Print(&buff)

	assert.JSONEq(t, `[
		{
		  "imageSignatureCheck": {
			"passed": false
		  },
		  "imageAccessibleCheck": {
			"passed": false
		  },
		  "attestationSignatureCheck": {
			"passed": false
		  },
		  "attestationSyntaxCheck": {
			"passed": false
		  },
		  "policyCheck": null
		},
		{
		  "imageSignatureCheck": {
			"passed": false
		  },
		  "imageAccessibleCheck": {
			"passed": false
		  },
		  "attestationSignatureCheck": {
			"passed": false
		  },
		  "attestationSyntaxCheck": {
			"passed": false
		  },
		  "policyCheck": null
		}
	  ]`, buff.String())
}

func Test_Violations(t *testing.T) {
	cases := []struct {
		name     string
		output   Output
		expected []output.Result
	}{
		{
			name: "passing",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: true,
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
			},
			expected: []output.Result{},
		},
		{
			name: "failing image signature",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &output.Result{Message: "image signature failed"},
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
			},
			expected: []output.Result{{Message: "image signature failed"}},
		},
		{
			name: "failing attestation signature",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: true,
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &output.Result{Message: "attestation signature failed"},
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
			},
			expected: []output.Result{{Message: "attestation signature failed"}},
		},
		{
			name: "failing attestation signature",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &output.Result{Message: "image signature failed"},
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &output.Result{Message: "attestation signature failed"},
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
			},
			expected: []output.Result{
				{Message: "image signature failed"},
				{Message: "attestation signature failed"},
			},
		},
		{
			name: "failing policy check",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: true,
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
				PolicyCheck: []output.CheckResult{
					{
						Failures: []output.Result{
							{
								Message: "failed policy check",
							},
						},
					},
				},
			},
			expected: []output.Result{{Message: "failed policy check"}},
		},
		{
			name: "failing multiple policy checks",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: true,
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
				PolicyCheck: []output.CheckResult{
					{
						Failures: []output.Result{
							{
								Message: "failed policy check 1",
							},
							{
								Message: "failed policy check 2",
							},
						},
					},
				},
			},
			expected: []output.Result{
				{Message: "failed policy check 1"},
				{Message: "failed policy check 2"}},
		},
		{
			name: "failing everything",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &output.Result{Message: "image signature failed"},
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &output.Result{Message: "attestation signature failed"},
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: false,
					Result: &output.Result{Message: "invalid attestation syntax"},
				},
				PolicyCheck: []output.CheckResult{
					{
						Failures: []output.Result{
							{
								Message: "failed policy check 1",
							},
							{
								Message: "failed policy check 2",
							},
						},
					},
				},
			},
			expected: []output.Result{
				{Message: "image signature failed"},
				{Message: "attestation signature failed"},
				{Message: "invalid attestation syntax"},
				{Message: "failed policy check 1"},
				{Message: "failed policy check 2"},
			},
		},
		{
			name: "mixed results",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &output.Result{Message: "image signature failed"},
				},
				ImageAccessibleCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: false,
					Result: &output.Result{Message: "attestation signature failed"},
				},
				AttestationSyntaxCheck: VerificationStatus{
					Passed: true,
				},
				PolicyCheck: []output.CheckResult{
					// Result with failures
					{
						Failures: []output.Result{
							{Message: "failure for policy check 1"},
							{Message: "failure for policy check 2"},
						},
					},
					// Result with warnings
					{
						Warnings: []output.Result{
							{Message: "warning for policy check 3"},
							{Message: "warning for policy check 4"},
						},
					},
					// Result without any failures nor warnings
					{},
					// Resuilt with both failures and warnings
					{
						Failures: []output.Result{
							{Message: "failure for policy check 5"},
							{Message: "failure for policy check 6"},
						},
						Warnings: []output.Result{
							{Message: "warning for policy check 7"},
							{Message: "warning for policy check 8"},
						},
					},
				},
			},
			expected: []output.Result{
				{Message: "image signature failed"},
				{Message: "attestation signature failed"},
				{Message: "failure for policy check 1"},
				{Message: "failure for policy check 2"},
				{Message: "failure for policy check 5"},
				{Message: "failure for policy check 6"},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expected, c.output.Violations())
		})
	}
}

func Test_Warnings(t *testing.T) {
	cases := []struct {
		name     string
		output   Output
		expected []output.Result
	}{
		{
			name:     "no-warnings",
			output:   Output{},
			expected: []output.Result{},
		},
		{
			name: "single warning",
			output: Output{
				PolicyCheck: []output.CheckResult{
					{
						Warnings: []output.Result{
							{Message: "warning for policy check 2"},
						},
					},
				},
			},
			expected: []output.Result{
				{Message: "warning for policy check 2"},
			},
		},
		{
			name: "multiple warnings",
			output: Output{
				PolicyCheck: []output.CheckResult{
					{
						Warnings: []output.Result{
							{Message: "warning for policy check 1"},
							{Message: "warning for policy check 2"},
						},
					},
				},
			},
			expected: []output.Result{
				{Message: "warning for policy check 1"},
				{Message: "warning for policy check 2"},
			},
		},
		{
			name: "mixed results",
			output: Output{
				ImageSignatureCheck: VerificationStatus{
					Passed: true,
				},
				AttestationSignatureCheck: VerificationStatus{
					Passed: true,
				},
				PolicyCheck: []output.CheckResult{
					// Result with failures
					{
						Failures: []output.Result{
							{Message: "failure for policy check 1"},
							{Message: "failure for policy check 2"},
						},
					},
					// Result with warnings
					{
						Warnings: []output.Result{
							{Message: "warning for policy check 3"},
							{Message: "warning for policy check 4"},
						},
					},
					// Result without any failures nor warnings
					{},
					// Resuilt with both failures and warnings
					{
						Failures: []output.Result{
							{Message: "failure for policy check 5"},
							{Message: "failure for policy check 6"},
						},
						Warnings: []output.Result{
							{Message: "warning for policy check 7"},
							{Message: "warning for policy check 8"},
						},
					},
				},
			},
			expected: []output.Result{
				{Message: "warning for policy check 3"},
				{Message: "warning for policy check 4"},
				{Message: "warning for policy check 7"},
				{Message: "warning for policy check 8"},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expected, c.output.Warnings())
		})
	}
}

func Test_SuccessCount(t *testing.T) {
	cases := []struct {
		name     string
		output   Output
		expected int
	}{
		{
			name:     "empty output",
			output:   Output{},
			expected: 0,
		},
		{
			name: "single success",
			output: Output{
				PolicyCheck: []output.CheckResult{
					{
						Successes: 1,
					},
				},
			},
			expected: 1,
		},
		{
			name: "multiple successes",
			output: Output{
				PolicyCheck: []output.CheckResult{
					{
						Successes: 2,
					},
				},
			},
			expected: 2,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expected, c.output.SuccessCount())
		})
	}
}

func TestSetImageAccessibleCheckFromError(t *testing.T) {
	cases := []struct {
		name           string
		err            error
		expectedPassed bool
		expectedResult *output.Result
	}{
		{
			name:           "success",
			expectedPassed: true,
		},
		{
			name:           "failure",
			expectedPassed: false,
			err:            errors.New("kaboom!"),
			expectedResult: &output.Result{
				Message: "Image URL is not accessible: kaboom!",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := Output{}
			o.SetImageAccessibleCheckFromError(c.err)

			assert.Equal(t, c.expectedPassed, o.ImageAccessibleCheck.Passed)
			assert.Equal(t, c.expectedResult, o.ImageAccessibleCheck.Result)
		})
	}
}

func TestSetImageSignatureCheckFromError(t *testing.T) {
	cases := []struct {
		name           string
		err            error
		expectedPassed bool
		expectedResult *output.Result
	}{
		{
			name:           "success",
			expectedPassed: true,
		},
		{
			name:           "generic failure",
			expectedPassed: false,
			err:            errors.New("kaboom!"),
			expectedResult: &output.Result{
				Message: "Image signature check failed: kaboom!",
			},
		},
		{
			name:           "missing signatures failure",
			expectedPassed: false,
			err:            fmt.Errorf("%w: kaboom!", cosign.ErrNoMatchingSignatures),
			expectedResult: &output.Result{
				Message: missingSignatureMessage,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := Output{}
			o.SetImageSignatureCheckFromError(c.err)

			assert.Equal(t, c.expectedPassed, o.ImageSignatureCheck.Passed)
			assert.Equal(t, c.expectedResult, o.ImageSignatureCheck.Result)
		})
	}
}
func TestSetAttestationSignatureCheckFromError(t *testing.T) {
	cases := []struct {
		name           string
		err            error
		expectedPassed bool
		expectedResult *output.Result
	}{
		{
			name:           "success",
			expectedPassed: true,
		},
		{
			name:           "generic failure",
			expectedPassed: false,
			err:            errors.New("kaboom!"),
			expectedResult: &output.Result{
				Message: "Image attestation check failed: kaboom!",
			},
		},
		{
			name:           "missing attestations failure",
			expectedPassed: false,
			err:            fmt.Errorf("%w: kaboom!", cosign.ErrNoMatchingAttestations),
			expectedResult: &output.Result{
				Message: missingAttestationMessage,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := Output{}
			o.SetAttestationSignatureCheckFromError(c.err)

			assert.Equal(t, c.expectedPassed, o.AttestationSignatureCheck.Passed)
			assert.Equal(t, c.expectedResult, o.AttestationSignatureCheck.Result)
		})
	}
}

func TestSetAttestationSyntaxCheckFromError(t *testing.T) {
	cases := []struct {
		name           string
		err            error
		expectedPassed bool
		expectedResult *output.Result
	}{
		{
			name:           "success",
			expectedPassed: true,
		},
		{
			name:           "failure",
			expectedPassed: false,
			err:            errors.New("kaboom!"),
			expectedResult: &output.Result{
				Message: "Attestation syntax check failed: kaboom!",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := Output{}
			o.SetAttestationSyntaxCheckFromError(c.err)

			assert.Equal(t, c.expectedPassed, o.AttestationSyntaxCheck.Passed)
			assert.Equal(t, c.expectedResult, o.AttestationSyntaxCheck.Result)
		})
	}
}
