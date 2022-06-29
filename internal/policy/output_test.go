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

package policy

import (
	"bytes"
	"testing"

	"github.com/open-policy-agent/conftest/output"
	"github.com/stretchr/testify/assert"
)

func Test_PrintExpectedJSON(t *testing.T) {
	output := Output{
		ImageSignatureCheck: VerificationStatus{
			Passed:  true,
			Message: "message1",
		},
		AttestationSignatureCheck: VerificationStatus{
			Passed:  false,
			Message: "message2",
		},
		PolicyCheck: []output.CheckResult{
			{
				FileName:  "file1.json",
				Namespace: "namespace1",
				Successes: 123,
				Skipped: []output.Result{
					{
						Message: "result11",
					},
					{
						Message: "result12",
					},
				},
				Warnings: []output.Result{
					{
						Message: "result13",
					},
					{
						Message: "result14",
					},
				},
				Failures: []output.Result{
					{
						Message: "result15",
					},
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
		ExitCode: 42,
	}

	var json bytes.Buffer
	output.Print(&json)

	assert.JSONEq(t, `{
		"imageSignatureCheck": {
		  "passed": true,
		  "message": "message1"
		},
		"attestationSignatureCheck": {
		  "passed": false,
		  "message": "message2"
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
		]
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
		  "attestationSignatureCheck": {
			"passed": false
		  },
		  "policyCheck": null
		},
		{
		  "imageSignatureCheck": {
			"passed": false
		  },
		  "attestationSignatureCheck": {
			"passed": false
		  },
		  "policyCheck": null
		}
	  ]`, buff.String())
}
