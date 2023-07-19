// Copyright Red Hat.
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

package validate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	conftestOutput "github.com/open-policy-agent/conftest/output"
	app "github.com/redhat-appstudio/application-api/api/v1alpha1"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/enterprise-contract/ec-cli/internal/applicationsnapshot"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/output"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

type data struct {
	imageRef string
	input    string
	filePath string
	images   string
}

func Test_determineInputSpec(t *testing.T) {
	cases := []struct {
		name      string
		arguments data
		spec      *app.SnapshotSpec
		err       string
	}{
		{
			name: "imageRef",
			arguments: data{
				imageRef: "registry/image:tag",
			},
			spec: &app.SnapshotSpec{
				Components: []app.SnapshotComponent{
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
			spec: &app.SnapshotSpec{},
		},
		{
			name: "faulty ApplicationSnapshot string",
			arguments: data{
				input: "{",
			},
			err: "unable to parse Snapshot specification from {: error converting YAML to JSON: yaml: line 1: did not find expected node content",
		},
		{
			name: "ApplicationSnapshot JSON string - images",
			arguments: data{
				images: `{
					"components": [
					  {
						"name": "nodejs",
						"containerImage": "quay.io/hacbs-contract-demo/single-nodejs-app:877418e"
					  }
					]
				}`,
			},
			spec: &app.SnapshotSpec{
				Application: "",
				Components: []app.SnapshotComponent{
					{
						Name:           "nodejs",
						ContainerImage: "quay.io/hacbs-contract-demo/single-nodejs-app:877418e",
					},
				},
			},
		},
		{
			name: "ApplicationSnapshot JSON string",
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
			spec: &app.SnapshotSpec{
				Application: "app1",
				Components: []app.SnapshotComponent{
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
			name: "ApplicationSnapshot YAML string",
			arguments: data{
				input: hd.Doc(`
					---
					application: app1
					components:
					- name: nodejs
					  containerImage: quay.io/hacbs-contract-demo/single-nodejs-app:877418e
					- name: petclinic
					  containerImage: quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f
					- name: single-container-app
					  containerImage: quay.io/hacbs-contract-demo/single-container-app:62c06bf
					`),
			},
			spec: &app.SnapshotSpec{
				Application: "app1",
				Components: []app.SnapshotComponent{
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
			spec: &app.SnapshotSpec{
				Application: "app1",
				Components: []app.SnapshotComponent{
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
			name: "ApplicationSnapshot file - images",
			arguments: data{
				images: "test_application_snapshot.json",
			},
			spec: &app.SnapshotSpec{
				Application: "app1",
				Components: []app.SnapshotComponent{
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
			s, err := applicationsnapshot.DetermineInputSpec(context.Background(), applicationsnapshot.Input{
				File:   c.arguments.filePath,
				JSON:   c.arguments.input,
				Image:  c.arguments.imageRef,
				Images: c.arguments.images,
			})
			if c.err != "" {
				assert.EqualError(t, err, c.err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, c.spec, s)
		})
	}
}

func Test_ValidateImageCommand(t *testing.T) {
	validate := func(_ context.Context, url string, _ policy.Policy, _ bool) (*output.Output, error) {
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
			PolicyCheck: evaluator.CheckResults{
				{
					CheckResult: conftestOutput.CheckResult{
						FileName:  "test.json",
						Namespace: "test.main",
						Successes: 1,
					},
					Successes: []conftestOutput.Result{
						{
							Message: "Pass",
							Metadata: map[string]interface{}{
								"code": "policy.nice",
							},
						},
					},
				},
			},
			ImageURL: url,
			ExitCode: 0,
		}, nil
	}

	cmd := validateImageCmd(validate)

	cmd.SetContext(utils.WithFS(context.TODO(), afero.NewMemMapFs()))

	effectiveTimeTest := time.Now().UTC().Format(time.RFC3339Nano)

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
		"--effective-time",
		effectiveTimeTest,
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": true,
		"ec-version": "development",
		"effective-time": %q,
		"key": %s,
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"source": {},
			"success": true
		  }
		],
		"policy": {
			"publicKey": %s
		}
	  }`, effectiveTimeTest, utils.TestPublicKeyJSON, utils.TestPublicKeyJSON), out.String())
}

func Test_ValidateImageCommandKeyless(t *testing.T) {
	called := false
	cmd := validateImageCmd(func(_ context.Context, url string, p policy.Policy, _ bool) (*output.Output, error) {
		assert.Equal(t, cosign.Identity{
			Issuer:        "my-certificate-oidc-issuer",
			Subject:       "my-certificate-identity",
			IssuerRegExp:  "my-certificate-oidc-issuer-regexp",
			SubjectRegExp: "my-certificate-identity-regexp",
		}, p.Identity())

		called = true

		return &output.Output{}, nil
	})

	cmd.SetContext(utils.WithFS(context.Background(), afero.NewMemMapFs()))

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--policy",
		"",
		"--certificate-identity",
		"my-certificate-identity",
		"--certificate-oidc-issuer",
		"my-certificate-oidc-issuer",
		"--certificate-identity-regexp",
		"my-certificate-identity-regexp",
		"--certificate-oidc-issuer-regexp",
		"my-certificate-oidc-issuer-regexp",
	})

	t.Setenv("EC_EXPERIMENTAL", "1")
	utils.SetTestFulcioRoots(t)
	utils.SetTestCTLogPublicKey(t)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.True(t, called)
}
func Test_ValidateImageCommandYAMLPolicyFile(t *testing.T) {
	validate := func(_ context.Context, url string, _ policy.Policy, _ bool) (*output.Output, error) {
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
			PolicyCheck: evaluator.CheckResults{
				{
					CheckResult: conftestOutput.CheckResult{
						FileName:  "test.json",
						Namespace: "test.main",
						Successes: 1,
					},
					Successes: []conftestOutput.Result{
						{
							Message: "Pass",
							Metadata: map[string]interface{}{
								"code": "policy.nice",
							},
						},
					},
				},
			},
			ImageURL: url,
			ExitCode: 0,
		}, nil
	}

	cmd := validateImageCmd(validate)

	fs := afero.NewMemMapFs()

	cmd.SetContext(utils.WithFS(context.TODO(), fs))

	testPolicyYaml := `sources:
  - policy:
      - "registry/policy:latest"
    data:
      - "registry/policy-data:latest"
configuration:
  collections:
    - minimal
  include:
    - "*"
  exclude: []
`
	err := afero.WriteFile(fs, "/policy.yaml", []byte(testPolicyYaml), 0644)
	if err != nil {
		panic(err)
	}
	args := []string{
		"--image",
		"registry/image:tag",
		"--public-key",
		utils.TestPublicKey,
		"--policy",
		"/policy.yaml",
	}
	cmd.SetArgs(args)

	var out bytes.Buffer
	cmd.SetOut(&out)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_ValidateImageCommandJSONPolicyFile(t *testing.T) {
	validate := func(_ context.Context, url string, _ policy.Policy, _ bool) (*output.Output, error) {
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
			PolicyCheck: evaluator.CheckResults{
				{
					CheckResult: conftestOutput.CheckResult{
						FileName:  "test.json",
						Namespace: "test.main",
						Successes: 1,
					},
					Successes: []conftestOutput.Result{
						{
							Message: "Pass",
							Metadata: map[string]interface{}{
								"code": "policy.nice",
							},
						},
					},
				},
			},
			ImageURL: url,
			ExitCode: 0,
		}, nil
	}

	cmd := validateImageCmd(validate)

	fs := afero.NewMemMapFs()

	cmd.SetContext(utils.WithFS(context.TODO(), fs))

	testPolicyJSON := `sources:
  - policy:
      - "registry/policy:latest"
    data:
      - "registry/policy-data:latest"
configuration:
  collections:
    - minimal
  include:
    - "*"
  exclude: []
`
	err := afero.WriteFile(fs, "/policy.json", []byte(testPolicyJSON), 0644)
	if err != nil {
		panic(err)
	}
	args := []string{
		"--image",
		"registry/image:tag",
		"--public-key",
		utils.TestPublicKey,
		"--policy",
		"/policy.json",
	}
	cmd.SetArgs(args)

	var out bytes.Buffer
	cmd.SetOut(&out)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_ValidateImageCommandEmptyPolicyFile(t *testing.T) {
	validate := func(_ context.Context, url string, _ policy.Policy, _ bool) (*output.Output, error) {
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
			PolicyCheck: evaluator.CheckResults{
				{
					CheckResult: conftestOutput.CheckResult{
						FileName:  "test.json",
						Namespace: "test.main",
						Successes: 1,
					},
					Successes: []conftestOutput.Result{
						{
							Message: "Pass",
							Metadata: map[string]interface{}{
								"code": "policy.nice",
							},
						},
					},
				},
			},
			ImageURL: url,
			ExitCode: 0,
		}, nil
	}

	cmd := validateImageCmd(validate)

	fs := afero.NewMemMapFs()

	cmd.SetContext(utils.WithFS(context.TODO(), fs))

	err := afero.WriteFile(fs, "/policy.yaml", []byte(nil), 0644)
	if err != nil {
		panic(err)
	}
	args := []string{
		"--image",
		"registry/image:tag",
		"--public-key",
		utils.TestPublicKey,
		"--policy",
		"/policy.yaml",
	}
	cmd.SetArgs(args)

	var out bytes.Buffer
	cmd.SetOut(&out)

	err = cmd.Execute()
	assert.EqualError(t, err, "1 error occurred:\n\t* file /policy.yaml is empty\n\n")
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
				fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
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
				`{"invalid": "json""}`,
			},
			expected: `1 error occurred:
	* unable to parse EnterpriseContractPolicySpec: error converting YAML to JSON: yaml: found unexpected end of stream

`,
		},
		{
			name: "invalid input JSON",
			args: []string{
				"--json-input",
				`{"invalid": "json""}`,
				"--policy",
				fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
			},
			expected: `1 error occurred:
	* unable to parse Snapshot specification from {"invalid": "json""}: error converting YAML to JSON: yaml: found unexpected end of stream

`,
		},
		{
			name: "invalid input and policy JSON",
			args: []string{
				"--json-input",
				`{"invalid": "json""}`,
				"--policy",
				`{"invalid": "json""}`,
			},
			expected: `2 errors occurred:
	* unable to parse Snapshot specification from {"invalid": "json""}: error converting YAML to JSON: yaml: found unexpected end of stream
	* unable to parse EnterpriseContractPolicySpec: error converting YAML to JSON: yaml: found unexpected end of stream

`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			validate := func(context.Context, string, policy.Policy, bool) (*output.Output, error) {
				return nil, errors.New("expected")
			}

			cmd := validateImageCmd(validate)

			cmd.SetContext(utils.WithFS(context.TODO(), afero.NewMemMapFs()))

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
	validate := func(_ context.Context, url string, _ policy.Policy, _ bool) (*output.Output, error) {
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

	cmd.SetContext(utils.WithFS(context.TODO(), afero.NewMemMapFs()))

	effectiveTimeTest := time.Now().UTC().Format(time.RFC3339Nano)

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
		"--effective-time",
		effectiveTimeTest,
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": false,
		"ec-version": "development",
		"effective-time": %q,
		"key": %s,
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"source": {},
			"violations": [
			  {"msg": "image ref not accessible. HEAD registry/image:tag: unexpected status code 404 Not Found (HEAD responses have no body, use GET for details)"},
			  {"msg": "skipped due to inaccessible image ref"},
			  {"msg": "skipped due to inaccessible image ref"}
			],
			"success": false
		  }
		],
		"policy": {
			"publicKey": %s
		}
	  }`, effectiveTimeTest, utils.TestPublicKeyJSON, utils.TestPublicKeyJSON), out.String())
}

func Test_FailureOutput(t *testing.T) {
	validate := func(_ context.Context, url string, _ policy.Policy, _ bool) (*output.Output, error) {
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

	cmd.SetContext(utils.WithFS(context.TODO(), afero.NewMemMapFs()))

	effectiveTimeTest := time.Now().UTC().Format(time.RFC3339Nano)

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
		"--effective-time",
		effectiveTimeTest,
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": false,
		"ec-version": "development",
		"effective-time": %q,
		"key": %s,
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"source": {},
			"violations": [
			  {"msg": "failed attestation signature check"},
			  {"msg": "failed image signature check"}
			],
			"success": false
		  }
		],
		"policy": {
			"publicKey": %s
		}
	  }`, effectiveTimeTest, utils.TestPublicKeyJSON, utils.TestPublicKeyJSON), out.String())
}

func Test_WarningOutput(t *testing.T) {
	validate := func(_ context.Context, url string, _ policy.Policy, _ bool) (*output.Output, error) {
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
			PolicyCheck: evaluator.CheckResults{
				{
					CheckResult: conftestOutput.CheckResult{
						Warnings: []conftestOutput.Result{
							{Message: "warning for policy check 1"},
							{Message: "warning for policy check 2"},
						},
					},
				},
			},
			ImageURL: url,
		}, nil
	}

	cmd := validateImageCmd(validate)

	cmd.SetContext(utils.WithFS(context.TODO(), afero.NewMemMapFs()))

	effectiveTimeTest := time.Now().UTC().Format(time.RFC3339Nano)

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": %s}`, utils.TestPublicKeyJSON),
		"--effective-time",
		effectiveTimeTest,
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": true,
		"ec-version": "development",
		"effective-time": %q,
		"key": %s,
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"source": {},
			"warnings": [
				{"msg": "warning for policy check 1"},
				{"msg": "warning for policy check 2"}
			],
			"success": true
		  }
		],
		"policy": {
			"publicKey": %s
		}
	  }`, effectiveTimeTest, utils.TestPublicKeyJSON, utils.TestPublicKeyJSON), out.String())
}
