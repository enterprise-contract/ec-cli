// Copyright The Enterprise Contract Contributors
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
	"sort"
	"time"

	"github.com/qri-io/jsonpointer"
	log "github.com/sirupsen/logrus"

	"github.com/enterprise-contract/ec-cli/internal/attestation"
	"github.com/enterprise-contract/ec-cli/internal/evaluation_target/application_snapshot_image"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/output"
	"github.com/enterprise-contract/ec-cli/internal/policy"
)

// ValidateImage executes the required method calls to evaluate a given policy
// against a given image url.
func ValidateImage(ctx context.Context, url string, p policy.Policy, detailed bool) (*output.Output, error) {
	log.Debugf("Validating image %s", url)

	out := &output.Output{ImageURL: url, Detailed: detailed, Policy: p}
	a, err := application_snapshot_image.NewApplicationSnapshotImage(ctx, url, p)
	if err != nil {
		log.Debug("Failed to create application snapshot image!")
		return nil, err
	}

	out.SetImageAccessibleCheckFromError(a.ValidateImageAccess(ctx))
	if !out.ImageAccessibleCheck.Passed {
		return out, nil
	}

	if resolved, err := resolveAndSetImageUrl(url, a); err != nil {
		return nil, err
	} else {
		out.ImageURL = resolved
	}

	if err := a.FetchImageConfig(ctx); err != nil {
		log.Debugf("Unable to fetch image config: %s", err)
	}
	if err := a.FetchParentImageConfig(ctx); err != nil {
		log.Debugf("Unable to fetch parent's image config: %s", err)
	}

	out.SetImageSignatureCheckFromError(a.ValidateImageSignature(ctx))

	out.SetAttestationSignatureCheckFromError(a.ValidateAttestationSignature(ctx))
	if !out.AttestationSignatureCheck.Passed {
		return out, nil
	}

	out.Signatures = a.Signatures()

	out.Attestations = a.Attestations()

	out.SetAttestationSyntaxCheckFromError(a.ValidateAttestationSyntax(ctx))

	if attestationTime := determineAttestationTime(ctx, a.Attestations()); attestationTime != nil {
		p.AttestationTime(*attestationTime)
	}

	att := a.Attestations()
	attCount := len(att)
	out.Attestations = att
	log.Debugf("Found %d attestations", attCount)
	if attCount == 0 {
		// This is very much a corner case.
		out.SetPolicyCheck([]evaluator.Outcome{
			{
				Failures: []evaluator.Result{{
					Message: "No attestations contain a subject that match the given image.",
				}},
			},
		})
		return out, nil
	}

	inputPath, inputJSON, err := a.WriteInputFile(ctx)
	if err != nil {
		log.Debug("Problem writing input files!")
		return nil, err
	}

	var allResults []evaluator.Outcome
	for _, e := range a.Evaluators {
		// Todo maybe: Handle each one concurrently
		results, data, err := e.Evaluate(ctx, []string{inputPath})
		defer e.Destroy()

		if err != nil {
			log.Debug("Problem running conftest policy check!")
			return nil, err
		}
		allResults = append(allResults, results...)
		out.Data = append(out.Data, data)
	}

	out.PolicyInput = inputJSON

	log.Debug("Conftest policy check complete")
	out.SetPolicyCheck(allResults)

	return out, nil
}

func resolveAndSetImageUrl(url string, asi *application_snapshot_image.ApplicationSnapshotImage) (string, error) {
	// Ensure image URL contains a digest to avoid ambiguity in the next
	// validation steps
	ref, err := ParseAndResolve(url)
	if err != nil {
		log.Debugf("Failed to parse image url %s", url)
		return "", err
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

	if err := asi.SetImageURL(resolved); err != nil {
		log.Debugf("Failed to set resolved image url %s", resolved)
		return "", err
	}

	return resolved, nil
}

func determineAttestationTime(ctx context.Context, attestations []attestation.Attestation) *time.Time {
	if len(attestations) == 0 {
		log.Debug("No attestations provided to determine attestation time")
		return nil
	}

	pointer, err := jsonpointer.Parse("/predicate/metadata/buildFinishedOn")
	if err != nil {
		log.Debugf("Failed to parse the fixed JSON Pointer: %v", err)
		panic(err)
	}

	times := make([]time.Time, 0, len(attestations))
	for i, attestation := range attestations {
		data := attestation.Statement()
		obj := map[string]any{}
		if err := json.Unmarshal(data, &obj); err != nil {
			continue
		}
		maybeFinishTime, err := pointer.Eval(obj)
		if err != nil {
			log.Debugf("Failed to evaluate JSON Pointer %s for attestation at %d", pointer, i)
			continue
		}

		finishTime, ok := maybeFinishTime.(string)
		if !ok {
			log.Debugf("Unexpected buildFinishedOn value for attestation at %d: %v", i, maybeFinishTime)
			continue
		}

		time, err := time.Parse(time.RFC3339, finishTime)
		if err != nil {
			log.Debugf("Unable to parse buildFinishedOn `%s` as RFC3339 time of attestation at %d", finishTime, i)
			continue
		}

		times = append(times, time.UTC())
	}

	if len(times) == 0 {
		return nil
	}

	sort.Slice(times, func(i, j int) bool {
		return times[i].After(times[j])
	})

	attestationTime := times[0]

	if log.IsLevelEnabled(log.DebugLevel) {
		log.Debugf("Determined attestation time: %s", attestationTime.Format(time.RFC3339))
	}

	return &attestationTime
}
