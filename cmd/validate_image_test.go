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

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	conftestOutput "github.com/open-policy-agent/conftest/output"
	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/applicationsnapshot"
	"github.com/hacbs-contract/ec-cli/internal/output"
	"github.com/hacbs-contract/ec-cli/internal/policy"
)

const mockPublicKey string = `-----BEGIN PUBLIC KEY-----\n` +
	`MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPEwqj1tPu2Uwti2abGgGgURluuad\n` +
	`BK1e0Opk9WTCJ6WyP8Yo3Dl9wNJnjfzBGoRocUsfSd8foGKnFX1E34xVzw==\n` +
	`-----END PUBLIC KEY-----\n`

type data struct {
	imageRef string
	input    string
	filePath string
}

func Test_determineInputSpec(t *testing.T) {
	cases := []struct {
		name      string
		arguments data
		spec      *appstudioshared.ApplicationSnapshotSpec
		err       string
	}{
		{
			name: "imageRef",
			arguments: data{
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
			arguments: data{
				input: "{}",
			},
			spec: &appstudioshared.ApplicationSnapshotSpec{},
		},
		{
			name: "faulty ApplicationSnapshot string",
			arguments: data{
				input: "/",
			},
			err: "invalid character '/' looking for beginning of value",
		},
		{
			name: "ApplicationSnapshot string",
			arguments: data{
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
			arguments: data{
				filePath: "test_application_snapshot.json",
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

	cases = cases[4:5]

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := applicationsnapshot.DetermineInputSpec(afero.NewOsFs(), c.arguments.filePath, c.arguments.input, c.arguments.imageRef)
			if c.err != "" {
				assert.EqualError(t, err, c.err)
			}
			assert.Equal(t, c.spec, s)
		})
	}
}

func Test_ValidateImageCommand(t *testing.T) {
	validate := func(_ context.Context, _ afero.Fs, url string, _ policy.Policy) (*output.Output, error) {
		return &output.Output{
			ImageSignatureCheck: output.VerificationStatus{
				Passed: true,
			},
			ImageAccessibleCheck: output.VerificationStatus{
				Passed: true,
			},
			AttestationSignatureCheck: output.VerificationStatus{
				Passed: true,
			},
			AttestationSyntaxCheck: output.VerificationStatus{
				Passed: true,
			},
			PolicyCheck: []conftestOutput.CheckResult{
				{
					FileName:  "test.json",
					Namespace: "test.main",
					Successes: 14,
				},
			},
			ImageURL: url,
			ExitCode: 0,
		}, nil
	}

	cmd := validateImageCmd(validate)

	cmd.SetContext(withFs(context.TODO(), afero.NewMemMapFs()))

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": "%s"}`, mockPublicKey),
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": true,
		"key": "%s",
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"violations": [],
			"warnings": [],
			"success": true
		  }
		]
	  }`, mockPublicKey), out.String())
}

func Test_ValidateErrorCommand(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name: "image validation failure",
			args: []string{
				"--image",
				"registry/image:tag",
				"--policy",
				fmt.Sprintf(`{"publicKey": "%s"}`, mockPublicKey),
			},
			expected: `1 error occurred:
	* error validating image registry/image:tag of component Unnamed: expected

`,
		},
		{
			name: "invalid policy JSON",
			args: []string{
				"--image",
				"registry/image:tag",
				"--policy",
				"{invalid JSON}",
			},
			expected: `1 error occurred:
	* unable to parse EnterpriseContractPolicy Spec: invalid character 'i' looking for beginning of object key string

`,
		},
		{
			name: "invalid input JSON",
			args: []string{
				"--json-input",
				"{invalid JSON}",
				"--policy",
				fmt.Sprintf(`{"publicKey": "%s"}`, mockPublicKey),
			},
			expected: `1 error occurred:
	* invalid character 'i' looking for beginning of object key string

`,
		},
		{
			name: "invalid input and policy JSON",
			args: []string{
				"--json-input",
				"{invalid JSON}",
				"--policy",
				"{invalid JSON}",
			},
			expected: `2 errors occurred:
	* invalid character 'i' looking for beginning of object key string
	* unable to parse EnterpriseContractPolicy Spec: invalid character 'i' looking for beginning of object key string

`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			validate := func(context.Context, afero.Fs, string, policy.Policy) (*output.Output, error) {
				return nil, errors.New("expected")
			}

			cmd := validateImageCmd(validate)

			cmd.SetContext(withFs(context.TODO(), afero.NewMemMapFs()))

			cmd.SetArgs(c.args)

			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true

			err := cmd.Execute()
			assert.EqualError(t, err, c.expected)
			assert.Empty(t, out.String())
		})
	}
}

func Test_FailureImageAccessibility(t *testing.T) {
	validate := func(_ context.Context, _ afero.Fs, url string, _ policy.Policy) (*output.Output, error) {
		return &output.Output{
			ImageSignatureCheck: output.VerificationStatus{
				Passed: false,
				Result: &conftestOutput.Result{Message: "skipped due to inaccessible image ref"},
			},
			ImageAccessibleCheck: output.VerificationStatus{
				Passed: false,
				Result: &conftestOutput.Result{Message: "image ref not accessible. HEAD registry/image:tag: unexpected status code 404 Not Found (HEAD responses have no body, use GET for details)"},
			},
			AttestationSignatureCheck: output.VerificationStatus{
				Passed: false,
				Result: &conftestOutput.Result{Message: "skipped due to inaccessible image ref"},
			},
			ImageURL: url,
		}, nil
	}

	cmd := validateImageCmd(validate)

	cmd.SetContext(withFs(context.TODO(), afero.NewMemMapFs()))

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": "%s"}`, mockPublicKey),
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": false,
		"key": "%s",
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"violations": [
			  {"msg": "skipped due to inaccessible image ref"},
			  {"msg": "image ref not accessible. HEAD registry/image:tag: unexpected status code 404 Not Found (HEAD responses have no body, use GET for details)"},
			  {"msg": "skipped due to inaccessible image ref"}
			],
			"warnings": [],
			"success": false
		  }
		]
	  }`, mockPublicKey), out.String())
}

func Test_FailureOutput(t *testing.T) {
	validate := func(_ context.Context, _ afero.Fs, url string, _ policy.Policy) (*output.Output, error) {
		return &output.Output{
			ImageSignatureCheck: output.VerificationStatus{
				Passed: false,
				Result: &conftestOutput.Result{Message: "failed image signature check"},
			},
			ImageAccessibleCheck: output.VerificationStatus{
				Passed: true,
			},
			AttestationSignatureCheck: output.VerificationStatus{
				Passed: false,
				Result: &conftestOutput.Result{Message: "failed attestation signature check"},
			},
			ImageURL: url,
		}, nil
	}

	cmd := validateImageCmd(validate)

	cmd.SetContext(withFs(context.TODO(), afero.NewMemMapFs()))

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": "%s"}`, mockPublicKey),
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": false,
		"key": "%s",
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"violations": [
			  {"msg": "failed image signature check"},
			  {"msg": "failed attestation signature check"}
			],
			"warnings": [],
			"success": false
		  }
		]
	  }`, mockPublicKey), out.String())
}

func Test_WarningOutput(t *testing.T) {
	validate := func(_ context.Context, _ afero.Fs, url string, _ policy.Policy) (*output.Output, error) {
		return &output.Output{
			ImageSignatureCheck: output.VerificationStatus{
				Passed: true,
			},
			ImageAccessibleCheck: output.VerificationStatus{
				Passed: true,
			},
			AttestationSignatureCheck: output.VerificationStatus{
				Passed: true,
			},
			PolicyCheck: []conftestOutput.CheckResult{
				{
					Warnings: []conftestOutput.Result{
						{Message: "warning for policy check 1"},
						{Message: "warning for policy check 2"},
					},
				},
			},
			ImageURL: url,
		}, nil
	}

	cmd := validateImageCmd(validate)

	cmd.SetContext(withFs(context.TODO(), afero.NewMemMapFs()))

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": "%s"}`, mockPublicKey),
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": true,
		"key": "%s",
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"violations": [],
			"warnings": [
				{"msg": "warning for policy check 1"},
				{"msg": "warning for policy check 2"}
			],
			"success": true
		  }
		]
	  }`, mockPublicKey), out.String())
}
