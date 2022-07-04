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

package cmd

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/hacbs-contract/ec-cli/internal/policy"
	"github.com/open-policy-agent/conftest/output"
	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/stretchr/testify/assert"
)

func Test_determineInputSpec(t *testing.T) {
	cases := []struct {
		name      string
		arguments args
		spec      *appstudioshared.ApplicationSnapshotSpec
		err       string
	}{
		{
			name: "imageRef",
			arguments: args{
				imageRef: "registry/image:tag",
			},
			spec: &appstudioshared.ApplicationSnapshotSpec{
				Components: []appstudioshared.ApplicationSnapshotComponent{
					{
						Name:           "Unnamed",
						ContainerImage: "registry/image:tag",
					},
				},
			},
		},
		{
			name: "empty ApplicationSnapshot string",
			arguments: args{
				input: "{}",
			},
			spec: &appstudioshared.ApplicationSnapshotSpec{},
		},
		{
			name: "faulty ApplicationSnapshot string",
			arguments: args{
				input: "/",
			},
			err: "invalid character '/' looking for beginning of value",
		},
		{
			name: "ApplicationSnapshot string",
			arguments: args{
				input: `{
					"application": "app1",
					"components": [
					  {
						"name": "nodejs",
						"containerImage": "quay.io/hacbs-contract-demo/single-nodejs-app:877418e"
					  },
					  {
						"name": "petclinic",
						"containerImage": "quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f"
					  },
					  {
						"name": "single-container-app",
						"containerImage": "quay.io/hacbs-contract-demo/single-container-app:62c06bf"
					  }
					]
				  }`,
			},
			spec: &appstudioshared.ApplicationSnapshotSpec{
				Application: "app1",
				Components: []appstudioshared.ApplicationSnapshotComponent{
					{
						Name:           "nodejs",
						ContainerImage: "quay.io/hacbs-contract-demo/single-nodejs-app:877418e",
					},
					{
						Name:           "petclinic",
						ContainerImage: "quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f",
					},
					{
						Name:           "single-container-app",
						ContainerImage: "quay.io/hacbs-contract-demo/single-container-app:62c06bf",
					},
				},
			},
		},
		{
			name: "ApplicationSnapshot file",
			arguments: args{
				filepath: "test_application_snapshot.json",
			},
			spec: &appstudioshared.ApplicationSnapshotSpec{
				Application: "app1",
				Components: []appstudioshared.ApplicationSnapshotComponent{
					{
						Name:           "nodejs",
						ContainerImage: "quay.io/hacbs-contract-demo/single-nodejs-app:877418e",
					},
					{
						Name:           "petclinic",
						ContainerImage: "quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f",
					},
					{
						Name:           "single-container-app",
						ContainerImage: "quay.io/hacbs-contract-demo/single-container-app:62c06bf",
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := determineInputSpec(c.arguments)
			if c.err != "" {
				assert.EqualError(t, err, c.err)
			}
			assert.Equal(t, c.spec, s)
		})
	}
}

func Test_ValidateImageCommand(t *testing.T) {
	validate := func(ctx context.Context, imageRef, policyConfiguration, publicKey, rekorURL string) (*policy.Output, error) {
		return &policy.Output{
			ImageSignatureCheck: policy.VerificationStatus{
				Passed: true,
			},
			AttestationSignatureCheck: policy.VerificationStatus{
				Passed: true,
			},
			PolicyCheck: []output.CheckResult{
				{
					FileName:  "test.json",
					Namespace: "test.main",
					Successes: 14,
				},
			},
			ExitCode: 0,
		}, nil
	}

	cmd := evalCmd(validate)

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--public-key",
		"test-public-key",
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, `{
		"success": true,
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"violations": [],
			"success": true
		  }
		]
	  }`, out.String())
}

func Test_ValidateErrorCommand(t *testing.T) {
	validate := func(ctx context.Context, imageRef, policyConfiguration, publicKey, rekorURL string) (*policy.Output, error) {
		return nil, errors.New("expected")
	}

	cmd := evalCmd(validate)

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--public-key",
		"test-public-key",
	})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true

	err := cmd.Execute()
	assert.EqualError(t, err, `1 error occurred:
	* error validating image registry/image:tag of component Unnamed: expected

`)
	assert.Empty(t, out.String())
}

func Test_FailureOutput(t *testing.T) {
	validate := func(ctx context.Context, imageRef, policyConfiguration, publicKey, rekorURL string) (*policy.Output, error) {
		return &policy.Output{
			ImageSignatureCheck: policy.VerificationStatus{
				Passed:  false,
				Message: "failed image signature check",
			},
			AttestationSignatureCheck: policy.VerificationStatus{
				Passed:  false,
				Message: "failed attestation signature check",
			},
		}, nil
	}

	cmd := evalCmd(validate)

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--public-key",
		"test-public-key",
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, `{
		"success": false,
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"violations": [
			  "failed image signature check",
			  "failed attestation signature check"
			],
			"success": false
		  }
		]
	  }`, out.String())
}

type mockImageValidator struct {
	validateImageErr       error
	validateAttestationErr error
	attestations           []oci.Signature
}

func (m mockImageValidator) ValidateImageSignature(context.Context) error {
	return m.validateImageErr
}

func (m mockImageValidator) ValidateAttestationSignature(context.Context) error {
	return m.validateAttestationErr
}

func (m mockImageValidator) Attestations() []oci.Signature {
	return m.attestations
}

type mockPolicyEvaluator struct {
	result []output.CheckResult
	err    error
}

func (m mockPolicyEvaluator) Evaluate(ctx context.Context, attestations []oci.Signature) ([]output.CheckResult, error) {
	if len(attestations) == 0 {
		return nil, m.err
	}

	return m.result, m.err
}

func Test_validateImageWith(t *testing.T) {
	cases := []struct {
		name                       string
		policyResult               []output.CheckResult
		policyError                error
		imageValidationError       error
		attestationValidationError error
		attestations               []oci.Signature
		expected                   *policy.Output
		expectedErr                error
	}{
		{
			name: "all passed",
			policyResult: []output.CheckResult{
				{},
			},
			attestations: make([]oci.Signature, 1),
			expected: &policy.Output{
				ImageSignatureCheck: policy.VerificationStatus{
					Passed:  true,
					Message: "success",
				},
				AttestationSignatureCheck: policy.VerificationStatus{
					Passed:  true,
					Message: "success",
				},
				PolicyCheck: []output.CheckResult{
					{},
				},
			},
		},
		{
			name:                 "image failed",
			imageValidationError: errors.New("image failed"),
			policyResult: []output.CheckResult{
				{},
			},
			expected: &policy.Output{
				ImageSignatureCheck: policy.VerificationStatus{
					Passed:  false,
					Message: "image failed",
				},
				AttestationSignatureCheck: policy.VerificationStatus{
					Passed:  true,
					Message: "success",
				},
			},
		},
		{
			name:                       "attestation failed",
			attestationValidationError: errors.New("attestation failed"),
			policyResult: []output.CheckResult{
				{},
			},
			expected: &policy.Output{
				ImageSignatureCheck: policy.VerificationStatus{
					Passed:  true,
					Message: "success",
				},
				AttestationSignatureCheck: policy.VerificationStatus{
					Passed:  false,
					Message: "attestation failed",
				},
			},
		},
		{
			name:        "policy evaluation failure",
			policyError: errors.New("policy evaluation failure"),
			expectedErr: errors.New("policy evaluation failure"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			out, err := validateImageWith(context.TODO(), "registry/image:tag", "policy-config", "public-key", "https://rekor.url", mockImageValidator{
				validateImageErr:       c.imageValidationError,
				validateAttestationErr: c.attestationValidationError,
				attestations:           c.attestations,
			}, mockPolicyEvaluator{
				result: c.policyResult,
				err:    c.policyError,
			})

			assert.Equal(t, c.expectedErr, err)
			assert.Equal(t, c.expected, out)
		})
	}
}
