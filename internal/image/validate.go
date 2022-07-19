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
	"encoding/json"
	"errors"
	"io/ioutil"

	conftestOutput "github.com/open-policy-agent/conftest/output"
	log "github.com/sirupsen/logrus"

	"github.com/hacbs-contract/ec-cli/internal/evaluation_target/application_snapshot_image"
	"github.com/hacbs-contract/ec-cli/internal/output"
)

// ValidateImage executes the required method calls to evaluate a given policy against a given imageRef
func ValidateImage(ctx context.Context, imageRef, policyConfiguration, publicKey, rekorURL string) (*output.Output, error) {
	log.Debugf("Validating image %s", imageRef)
	out := &output.Output{}
	a, err := application_snapshot_image.NewApplicationSnapshotImage(ctx, imageRef, publicKey, rekorURL, policyConfiguration)
	if err != nil {
		log.Debug("Failed to create application snapshot image!")
		return nil, err
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
	}
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

	inputs, err := a.WriteInputFiles(ctx)
	if err != nil {
		log.Debug("Problem writing input files!")
		return nil, err
	}

	attStatements := make([]attestation, 0, len(a.Attestations()))
	for _, att := range a.Attestations() {
		attStatement, err := SignatureToAttestation(ctx, att)
		if err != nil {
			return nil, err
		}
		attStatements = append(attStatements, attStatement)
	}

	commitFile := "/tmp/commit.json"
	writeCommitData(attStatements, commitFile)

	inputs = append(inputs, commitFile)

	results, err := a.Evaluator.Evaluate(ctx, inputs)

	if err != nil {
		log.Debug("Problem running conftest policy check!")
		return nil, err
	}

	log.Debug("Conftest policy check complete")
	out.SetPolicyCheck(results)

	return out, nil
}

func writeCommitData(attestations []attestation, commitFile string) error {
	payloads := make([]*signOffSignature, 0, len(attestations))
	for _, att := range attestations {
		signoffSource, err := att.NewSignOffSource()
		if err != nil {
			return err
		}
		if signoffSource == nil {
			return errors.New("there is no signoff source in attestation")
		}

		signOff, err := signoffSource.GetSignOff()
		if err != nil {
			return err
		}

		if signOff != nil {
			payloads = append(payloads, signOff)
		}
	}

	payloadJson, _ := json.Marshal(payloads)
	_ = ioutil.WriteFile(commitFile, payloadJson, 0644)
	return nil
}
