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

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/qri-io/jsonschema"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	cosignPolicy "github.com/sigstore/cosign/pkg/policy"
	cosignTypes "github.com/sigstore/cosign/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/hacbs-contract/ec-cli/internal/evaluator"
	"github.com/hacbs-contract/ec-cli/internal/policy"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
	ece "github.com/hacbs-contract/ec-cli/pkg/error"
	"github.com/hacbs-contract/ec-cli/pkg/schema"
)

var (
	EV001 = ece.NewError("EV001", "No attestation data", ece.ErrorExitStatus)
	EV002 = ece.NewError("EV002", "Unable to decode attestation data from attestation image", ece.ErrorExitStatus)
	EV003 = ece.NewError("EV003", "Attestation syntax validation failed", ece.ErrorExitStatus)
)

// ConftestNamespace is the default rego namespace using for policy evaluation
const ConftestNamespace = "release.main"

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
	attestations []oci.Signature
	signatures   []cosign.Signatures
	Evaluators   []evaluator.Evaluator
}

// NewApplicationSnapshotImage returns an ApplicationSnapshotImage struct with reference, checkOpts, and evaluator ready to use.
func NewApplicationSnapshotImage(ctx context.Context, fs afero.Fs, url string, p *policy.Policy) (*ApplicationSnapshotImage, error) {
	a := &ApplicationSnapshotImage{
		checkOpts: *p.CheckOpts,
	}

	if err := a.SetImageURL(url); err != nil {
		return nil, err
	}

	if p.CheckOpts.RekorClient != nil {
		// By using Cosign directly the log entries are validated against the
		// Rekor public key, the public key for Rekor can be supplied via three
		// different means:
		// - TUF, which is hardcoded to
		//   https://sigstore-tuf-root.storage.googleapis.com
		// - SIGSTORE_REKOR_PUBLIC_KEY environment variable, which emits warning
		//   to stderr
		// - SIGSTORE_TRUST_REKOR_API_PUBLIC_KEY to fetch the public key via the
		//   Rekor API
		// Here we opt for the last option as we can't influence the first
		// option and the second option unconditionally prints to standard
		// error.
		// TODO: Ideally we would have a --rekor-public-key parameter to pass in
		// the Rekor public key in addition to having TUF setup which makes it
		// easier to rotate keys
		os.Setenv("SIGSTORE_TRUST_REKOR_API_PUBLIC_KEY", "1")
	}

	// Return an evaluator for each of these
	for _, sourceGroup := range p.EnterpriseContractPolicySpec.Sources {
		// Todo: Make each fetch run concurrently
		log.Debugf("Fetching policy source group '%s'", sourceGroup.Name)
		policySources, err := fetchPolicySources(&sourceGroup)
		if err != nil {
			log.Debugf("Failed to fetch policy source group '%s'!", sourceGroup.Name)
			return nil, err
		}

		for _, policySource := range policySources {
			log.Debugf("policySource: %#v", policySource)
		}

		c, err := newConftestEvaluator(ctx, fs, policySources, ConftestNamespace, p)
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
func fetchPolicySources(s *ecc.Source) ([]source.PolicySource, error) {
	policySources := make([]source.PolicySource, 0, len(s.Policy)+len(s.Data))

	for _, policySourceUrl := range s.Policy {
		url := source.PolicyUrl{Url: policySourceUrl, Kind: "policy"}
		policySources = append(policySources, &url)
	}

	for _, dataSourceUrl := range s.Data {
		url := source.PolicyUrl{Url: dataSourceUrl, Kind: "data"}
		policySources = append(policySources, &url)
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
	resp, err := remote.Head(a.reference, opts...)
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
	a.attestations = []oci.Signature{}
	a.signatures = []cosign.Signatures{}

	return nil
}

// ValidateImageSignature executes the cosign.VerifyImageSignature method on the ApplicationSnapshotImage image ref.
func (a *ApplicationSnapshotImage) ValidateImageSignature(ctx context.Context) error {
	_, _, err := cosign.VerifyImageSignatures(ctx, a.reference, &a.checkOpts)
	return err
}

// ValidateAttestationSignature executes the cosign.VerifyImageAttestations method
func (a *ApplicationSnapshotImage) ValidateAttestationSignature(ctx context.Context) error {
	attestations, _, err := cosign.VerifyImageAttestations(ctx, a.reference, &a.checkOpts)
	if err != nil {
		return err
	}
	a.attestations = attestations

	// Extract the signatures from the attestations here in order to also validate that
	// the signatures do exist in the expected format.
	for _, att := range attestations {
		signatures, err := signaturesFrom(ctx, att)
		if err != nil {
			return err
		}
		a.signatures = append(a.signatures, signatures...)
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
	for _, att := range a.attestations {
		statementBytes, _, err := statementFrom(ctx, att)
		if err != nil {
			return EV002.CausedBy(err)
		}
		if statementBytes == nil {
			return EV002.CausedByF("Unrecognized statement JSON")
		}

		// at least one of the schemas needs to pass validation
		for id, schema := range attestationSchemas {
			if errs, err := schema.ValidateBytes(ctx, statementBytes); err != nil {
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

// FilterMatchingAttestations ignores attestations that do not have a matching subject.
func (a *ApplicationSnapshotImage) FilterMatchingAttestations(ctx context.Context) {
	filteredAttestations := make([]oci.Signature, 0, len(a.attestations))
	for _, attestation := range a.attestations {
		_, statement, err := statementFrom(ctx, attestation)
		if err != nil {
			log.Debugf("Unable to extract statement from attestation: %v", err)
			continue
		}
		identifier := a.reference.Identifier()
		if matchDigest(statement.Subject, identifier) {
			filteredAttestations = append(filteredAttestations, attestation)
		} else {
			log.Warnf(
				"Ignoring attestation, none of its subjects (%v) match the image identifier %q",
				statement.Subject, identifier)
		}
	}
	a.attestations = filteredAttestations
}

// matchDigest returns true if any of the subjects match the given digest.
func matchDigest(subjects []in_toto.Subject, digest string) bool {
	for _, subject := range subjects {
		for algo, value := range subject.Digest {
			subjectIdentifier := fmt.Sprintf("%s:%s", algo, value)
			if digest == subjectIdentifier {
				return true
			}
		}
	}
	return false
}

// Attestations returns the value of the attestations field of the ApplicationSnapshotImage struct
func (a *ApplicationSnapshotImage) Attestations() []oci.Signature {
	return a.attestations
}

func (a *ApplicationSnapshotImage) Signatures() []cosign.Signatures {
	return a.signatures
}

// WriteInputFiles writes the JSON from the attestations to input.json in a random temp dir
func (a *ApplicationSnapshotImage) WriteInputFiles(ctx context.Context, fs afero.Fs) ([]string, error) {
	attCount := len(a.attestations)
	log.Debugf("Attempting to write %d attestations to inputs", attCount)
	inputs := make([]string, 0, attCount)

	for _, att := range a.attestations {
		_, statement, err := statementFrom(ctx, att)
		if err != nil {
			return nil, err
		}
		if statement == nil {
			continue
		}

		inputDir, err := afero.TempDir(fs, "", "ecp_input.")
		if err != nil {
			log.Debug("Problem making temp dir!")
			return nil, err
		}
		log.Debugf("Created dir %s", inputDir)
		inputJSONPath := path.Join(inputDir, "input.json")

		f, err := fs.OpenFile(inputJSONPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0644)
		if err != nil {
			log.Debugf("Problem creating file in %s", inputDir)
			return nil, err
		}
		defer f.Close()
		j := json.NewEncoder(f)

		attestations := map[string][]in_toto.Statement{
			"attestations": {
				*statement,
			},
		}

		err = j.Encode(attestations)
		if err != nil {
			log.Debug("Problem encoding attestion JSON!")
			return nil, err
		}

		inputs = append(inputs, inputJSONPath)
	}

	log.Debugf("Done preparing inputs:\n%s", inputs)
	return inputs, nil
}

func statementFrom(ctx context.Context, att oci.Signature) ([]byte, *in_toto.Statement, error) {
	if att == nil {
		log.Debug("nil oci.Signature provided")
		return nil, nil, errors.New("no signature provided")
	}
	typ, err := att.MediaType()
	if err != nil {
		log.Debug("Problem finding media type!")
		return nil, nil, err
	}

	if typ != cosignTypes.DssePayloadType {
		log.Debugf("Skipping unexpected media type %s", typ)
		return nil, nil, nil
	}
	payload, err := cosignPolicy.AttestationToPayloadJSON(ctx, "slsaprovenance", att)
	if err != nil {
		log.Debug("Problem extracting json payload from attestation!")
		return nil, nil, err
	}

	if len(payload) == 0 {
		log.Debug("Empty attestation payload json (could be wrong type)!")
		return nil, nil, nil
	}

	var statement in_toto.Statement
	err = json.Unmarshal(payload, &statement)
	if err != nil {
		log.Debug("Problem parsing attestation payload json!")
		return nil, nil, err
	}

	return payload, &statement, nil
}

func signaturesFrom(ctx context.Context, att oci.Signature) ([]cosign.Signatures, error) {
	rawPayload, err := att.Payload()
	if err != nil {
		log.Debug("Problem extracting json payload from attestation!")
		return nil, err
	}

	var attestationPayload cosign.AttestationPayload
	if err := json.Unmarshal(rawPayload, &attestationPayload); err != nil {
		return nil, err
	}

	return attestationPayload.Signatures, nil
}
