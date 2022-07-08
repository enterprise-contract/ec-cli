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

package image

import (
	"context"

	conftestOutput "github.com/open-policy-agent/conftest/output"

	"github.com/hacbs-contract/ec-cli/internal/evaluation_target/application_snapshot_image"
	"github.com/hacbs-contract/ec-cli/internal/output"
)

// ValidateImage executes the required method calls to evaluate a given policy against a given imageRef
func ValidateImage(ctx context.Context, imageRef, policyConfiguration, publicKey, rekorURL string) (*output.Output, error) {
	out := &output.Output{}
	a, err := application_snapshot_image.NewApplicationSnapshotImage(ctx, imageRef, publicKey, rekorURL, policyConfiguration)
	if err != nil {
		return nil, err
	}

	if err = a.ValidateImageSignature(); err != nil {
		out.SetImageSignatureCheck(false, err.Error())
	} else {
		out.SetImageSignatureCheck(true, "success")
	}

	if err = a.ValidateAttestationSignature(); err != nil {
		out.SetAttestationSignatureCheck(false, err.Error())
	} else {
		out.SetAttestationSignatureCheck(true, "success")
	}
	if len(a.Attestations()) == 0 {
		res := []conftestOutput.CheckResult{
			{
				Failures: []conftestOutput.Result{
					{
						Message: "no attestations available",
					},
				},
			},
		}
		out.SetPolicyCheck(res)
		return out, nil
	}

	inputs, err := a.WriteInputFiles()
	if err != nil {
		return nil, err
	}

	results, err := a.Evaluator.TestRunner.Run(a.Evaluator.Context, inputs)

	if err != nil {
		return nil, err
	}
	out.SetPolicyCheck(results)

	return out, nil
}
