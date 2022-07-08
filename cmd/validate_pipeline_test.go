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

	"github.com/open-policy-agent/conftest/output"
	"github.com/stretchr/testify/assert"

	output2 "github.com/hacbs-contract/ec-cli/internal/output"
	"github.com/hacbs-contract/ec-cli/internal/policy_source"
)

func Test_ValidatePipelineCommandOutput(t *testing.T) {
	validate := func(ctx context.Context, fpath string, policyRepo policy_source.PolicyRepo, namespace string) (*output2.Output, error) {
		return &output2.Output{
			PolicyCheck: []output.CheckResult{
				{
					FileName:  fpath,
					Namespace: namespace,
				},
			},
		}, nil
	}

	cmd := validatePipelineCmd(validate)

	var out bytes.Buffer
	cmd.SetOut(&out)

	cmd.SetArgs([]string{
		"--pipeline-file",
		"/path/file1.yaml",
		"--pipeline-file",
		"/path/file2.yaml",
	})

	err := cmd.Execute()
	assert.NoError(t, err)

	assert.JSONEq(t, `[
		{
		  "imageSignatureCheck": {
			"passed": false
		  },
		  "attestationSignatureCheck": {
			"passed": false
		  },
		  "policyCheck": [
			{
			  "filename": "/path/file1.yaml",
			  "namespace": "pipeline.main",
			  "successes": 0
			}
		  ]
		},
		{
		  "imageSignatureCheck": {
			"passed": false
		  },
		  "attestationSignatureCheck": {
			"passed": false
		  },
		  "policyCheck": [
			{
			  "filename": "/path/file2.yaml",
			  "namespace": "pipeline.main",
			  "successes": 0
			}
		  ]
		}
	  ]`, out.String())
}

func Test_ValidatePipelineCommandErrors(t *testing.T) {
	validate := func(ctx context.Context, fpath string, policyRepo policy_source.PolicyRepo, namespace string) (*output2.Output, error) {
		return nil, errors.New(fpath)
	}

	cmd := validatePipelineCmd(validate)

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SilenceUsage = true

	cmd.SetArgs([]string{
		"--pipeline-file",
		"/path/file1.yaml",
		"--pipeline-file",
		"/path/file2.yaml",
	})

	err := cmd.Execute()
	assert.Error(t, err, "2 errors occurred:\n\t* /path/file1.yaml\n\t* /path/file2.yaml\n")

	assert.JSONEq(t, `[]`, out.String())
}
