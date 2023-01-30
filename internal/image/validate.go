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
	"fmt"

	conftestOutput "github.com/open-policy-agent/conftest/output"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/hacbs-contract/ec-cli/internal/evaluation_target/application_snapshot_image"
	"github.com/hacbs-contract/ec-cli/internal/output"
	"github.com/hacbs-contract/ec-cli/internal/policy"
)

// ValidateImage executes the required method calls to evaluate a given policy
// against a given image url.
func ValidateImage(ctx context.Context, fs afero.Fs, url string, p *policy.Policy) (*output.Output, error) {
	log.Debugf("Validating image %s", url)

	out := &output.Output{ImageURL: url}
	a, err := application_snapshot_image.NewApplicationSnapshotImage(ctx, fs, url, p)
	if err != nil {
		log.Debug("Failed to create application snapshot image!")
		return nil, err
	}

	if err = a.ValidateImageAccess(ctx); err != nil {
		log.Debugf("Image access check failed. Error: %s", err.Error())
		out.SetImageAccessibleCheck(false, fmt.Sprintf("image ref not accessible. %s", err))
		out.SetImageSignatureCheck(false, "")
		out.SetAttestationSignatureCheck(false, "")
		out.SetPolicyCheck(nil)
		return out, nil
	} else {
		log.Debug("Image access check passed")
		out.SetImageAccessibleCheck(true, "success")

		// Ensure image URL contains a digest to avoid ambiguity in the next
		// validation steps
		ref, err := ParseAndResolve(url)
		if err != nil {
			log.Debugf("Failed to parse image url %s", url)
			return nil, err
		}
		// The original image reference may or may not have had a tag. If it didn't,
		// the code above will set the tag to "latest". This is expected in some cases,
		// e.g. image ref also does not include digest. However, in other cases, although
		// harmless, it may cause confusion to users. The tag is cleared here to prevent
		// such confusion and to further emphasize that the image is only accessed by digest
		// from this point forward.
		ref.Tag = ""
		resolved := ref.String()
		log.Debugf("Resolved image to %s", resolved)
		if err := a.SetImageURL(resolved); err != nil {
			log.Debugf("Failed to set resolved image url %s", resolved)
			return nil, err
		}
		out.ImageURL = resolved
	}

	if err = a.ValidateImageSignature(ctx); err != nil {
		log.Debug("Image signature check failed")
		out.SetImageSignatureCheck(false, err.Error())
	} else {
		log.Debug("Image signature check passed")
		out.SetImageSignatureCheck(true, "success")
	}
	if err = a.ValidateAttestationSignature(ctx); err != nil {
		log.Debug("Image attestation signature check failed")
		out.SetAttestationSignatureCheck(false, err.Error())
	} else {
		log.Debug("Image attestation signature check passed")
		out.SetAttestationSignatureCheck(true, "success")
		out.Signatures = a.Signatures()
	}
	if err = a.ValidateAttestationSyntax(ctx); err != nil {
		log.Debug("Image attestation syntax check failed")
		out.SetAttestationSyntaxCheck(false, err.Error())
	} else {
		log.Debug("Image attestation syntax check passed")
		out.SetAttestationSyntaxCheck(true, "success")
	}

	a.FilterMatchingAttestations(ctx)

	attCount := len(a.Attestations())
	log.Debugf("Found %d attestations", attCount)
	if attCount == 0 {
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

	input, err := a.WriteInputFile(ctx, fs)
	if err != nil {
		log.Debug("Problem writing input files!")
		return nil, err
	}

	var allResults []conftestOutput.CheckResult
	for _, e := range a.Evaluators {
		// Todo maybe: Handle each one concurrently
		results, err := e.Evaluate(ctx, []string{input})

		if err != nil {
			log.Debug("Problem running conftest policy check!")
			return nil, err
		} else {
			allResults = append(allResults, results...)
		}
	}

	log.Debug("Conftest policy check complete")
	out.SetPolicyCheck(allResults)

	return out, nil
}
