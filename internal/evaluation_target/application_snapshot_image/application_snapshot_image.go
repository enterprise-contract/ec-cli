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

package application_snapshot_image

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/qri-io/jsonschema"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/enterprise-contract/ec-cli/internal/attestation"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/output"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/utils"
	ece "github.com/enterprise-contract/ec-cli/pkg/error"
	"github.com/enterprise-contract/ec-cli/pkg/schema"
)

var (
	EV001 = ece.NewError("EV001", "No attestation data", ece.ErrorExitStatus)
	EV002 = ece.NewError("EV002", "Unable to decode attestation data from attestation image", ece.ErrorExitStatus)
	EV003 = ece.NewError("EV003", "Attestation syntax validation failed", ece.ErrorExitStatus)
)

var newConftestEvaluator = evaluator.NewConftestEvaluator

// imageRefTransport is used to inject the type of transport to use with the
// remote.WithTransport function. By default, remote.DefaultTransport is
// equivalent to http.DefaultTransport, with a reduced timeout and keep-alive
var imageRefTransport = remote.WithTransport(remote.DefaultTransport)

var attestationSchemas = map[string]jsonschema.Schema{
	"https://slsa.dev/provenance/v0.2": schema.SLSA_Provenance_v0_2,
}

// ApplicationSnapshotImage represents the structure needed to evaluate an Application Snapshot Image
type ApplicationSnapshotImage struct {
	reference    name.Reference
	checkOpts    cosign.CheckOpts
	signatures   []output.EntitySignature
	attestations []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]
	Evaluators   []evaluator.Evaluator
}

// NewApplicationSnapshotImage returns an ApplicationSnapshotImage struct with reference, checkOpts, and evaluator ready to use.
func NewApplicationSnapshotImage(ctx context.Context, url string, p policy.Policy) (*ApplicationSnapshotImage, error) {
	opts, err := p.CheckOpts()
	if err != nil {
		return nil, err
	}
	a := &ApplicationSnapshotImage{
		checkOpts: *opts,
	}

	if err := a.SetImageURL(url); err != nil {
		return nil, err
	}

	// Return an evaluator for each of these
	for _, sourceGroup := range p.Spec().Sources {
		// Todo: Make each fetch run concurrently
		log.Debugf("Fetching policy source group '%s'", sourceGroup.Name)
		policySources, err := fetchPolicySources(sourceGroup)
		if err != nil {
			log.Debugf("Failed to fetch policy source group '%s'!", sourceGroup.Name)
			return nil, err
		}

		for _, policySource := range policySources {
			log.Debugf("policySource: %#v", policySource)
		}

		c, err := newConftestEvaluator(ctx, policySources, p)
		if err != nil {
			log.Debug("Failed to initialize the conftest evaluator!")
			return nil, err
		}

		log.Debug("Conftest evaluator initialized")
		a.Evaluators = append(a.Evaluators, c)
	}
	return a, nil
}

// fetchPolicySources returns an array of policy sources
func fetchPolicySources(s ecc.Source) ([]source.PolicySource, error) {
	policySources := make([]source.PolicySource, 0, len(s.Policy)+len(s.Data))

	for _, policySourceUrl := range s.Policy {
		url := source.PolicyUrl{Url: policySourceUrl, Kind: "policy"}
		policySources = append(policySources, &url)
	}

	for _, dataSourceUrl := range s.Data {
		url := source.PolicyUrl{Url: dataSourceUrl, Kind: "data"}
		policySources = append(policySources, &url)
	}

	if s.RuleData != nil {
		data := append(append([]byte(`{"rule_data__configuration__":`), s.RuleData.Raw...), '}')
		policySources = append(policySources, source.InlineData(data))
	}

	return policySources, nil
}

// ValidateImageAccess executes the remote.Head method on the ApplicationSnapshotImage image ref
func (a *ApplicationSnapshotImage) ValidateImageAccess(ctx context.Context) error {
	opts := []remote.Option{
		imageRefTransport,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}
	resp, err := NewClient(ctx).Head(a.reference, opts...)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("no response received")
	}
	log.Debugf("Resp: %+v", resp)
	return nil

}

func (a *ApplicationSnapshotImage) SetImageURL(url string) error {
	ref, err := name.ParseReference(url)
	if err != nil {
		log.Debugf("Failed to parse image url %s", url)
		return err
	}
	log.Debugf("Parsed image url %s", ref)
	a.reference = ref

	// Reset internal state relevant to the image
	a.attestations = []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{}
	a.signatures = []output.EntitySignature{}

	return nil
}

// ValidateImageSignature executes the cosign.VerifyImageSignature method on the ApplicationSnapshotImage image ref.
func (a *ApplicationSnapshotImage) ValidateImageSignature(ctx context.Context) error {
	// Set the ClaimVerifier on a shallow *copy* of CheckOpts to avoid unexpected side-effects
	opts := a.checkOpts
	opts.ClaimVerifier = cosign.SimpleClaimVerifier
	_, _, err := NewClient(ctx).VerifyImageSignatures(ctx, a.reference, &opts)
	return err
}

// ValidateAttestationSignature executes the cosign.VerifyImageAttestations method
func (a *ApplicationSnapshotImage) ValidateAttestationSignature(ctx context.Context) error {
	// Set the ClaimVerifier on a shallow *copy* of CheckOpts to avoid unexpected side-effects
	opts := a.checkOpts
	opts.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	layers, _, err := NewClient(ctx).VerifyImageAttestations(ctx, a.reference, &opts)
	if err != nil {
		return err
	}

	// Extract the signatures from the attestations here in order to also validate that
	// the signatures do exist in the expected format.

	for _, att := range layers {
		sp, err := attestation.SLSAProvenanceFromLayer(att)
		if err != nil {
			log.Debugf("Ignoring non SLSA Provenance attestation: %s", err)
			continue
		}
		a.attestations = append(a.attestations, sp)

		a.signatures = append(a.signatures, sp.Signatures()...)
	}
	return nil
}

// ValidateAttestationSyntax validates the attestations against known JSON
// schemas, errors out if there are no attestations to check to prevent
// sucessful syntax check of no inputs, must invoke
// [ValidateAttestationSignature] to prefill the attestations.
func (a ApplicationSnapshotImage) ValidateAttestationSyntax(ctx context.Context) error {
	if len(a.attestations) == 0 {
		log.Debug("No attestation data found, possibly due to attestation image signature not being validated beforehand")
		return EV001
	}

	allErrors := map[string][]jsonschema.KeyError{}
	for _, sp := range a.attestations {
		// at least one of the schemas needs to pass validation
		for id, schema := range attestationSchemas {
			if errs, err := schema.ValidateBytes(ctx, sp.Data()); err != nil {
				return EV002.CausedBy(err)
			} else {
				if len(errs) == 0 {
					// one schema validation suceeded, consider this a success
					// TODO: one possible drawback of this is that JSON schemas
					// are open by default, e.g. if additionalProperties=true
					// (the default) properties not defined in the schema are
					// allowed, which in turn means that the document might not
					// contain any of the properties declared in the schema
					continue
				}

				allErrors[id] = errs
				log.Debugf("Validated the statement against %s schema and found the following errors: %v", id, errs)
			}
		}
	}

	if len(allErrors) == 0 {
		// TODO another option might be to filter out invalid statement JSONs
		// and keep only the valid ones
		return nil
	}

	log.Debug("Failed to validate statements from the attastation image against all known schemas")
	msg := ""
	for id, errs := range allErrors {
		msg += fmt.Sprintf("\nSchema ID: %s", id)
		for _, e := range errs {
			msg += fmt.Sprintf("\n - %s", e.Error())
		}
	}
	return EV003.CausedBy(errors.New(msg))
}

// Attestations returns the value of the attestations field of the ApplicationSnapshotImage struct
func (a *ApplicationSnapshotImage) Attestations() []attestation.Attestation[in_toto.ProvenanceStatementSLSA02] {
	return a.attestations
}

func (a *ApplicationSnapshotImage) Signatures() []output.EntitySignature {
	return a.signatures
}

// WriteInputFile writes the JSON from the attestations to input.json in a random temp dir
func (a *ApplicationSnapshotImage) WriteInputFile(ctx context.Context) (string, error) {
	log.Debugf("Attempting to write %d attestations to input file", len(a.attestations))

	var statements []in_toto.ProvenanceStatementSLSA02
	for _, sp := range a.attestations {
		statements = append(statements, sp.Statement())
	}
	attestations := map[string][]in_toto.ProvenanceStatementSLSA02{"attestations": statements}

	fs := utils.FS(ctx)
	inputDir, err := afero.TempDir(fs, "", "ecp_input.")
	if err != nil {
		log.Debug("Problem making temp dir!")
		return "", err
	}
	log.Debugf("Created dir %s", inputDir)
	inputJSONPath := path.Join(inputDir, "input.json")

	f, err := fs.OpenFile(inputJSONPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0644)
	if err != nil {
		log.Debugf("Problem creating file in %s", inputDir)
		return "", err
	}
	defer f.Close()

	j := json.NewEncoder(f)
	err = j.Encode(attestations)
	if err != nil {
		log.Debug("Problem encoding attestion JSON!")
		return "", err
	}

	log.Debugf("Done preparing input file:\n%s", inputJSONPath)
	return inputJSONPath, nil
}
