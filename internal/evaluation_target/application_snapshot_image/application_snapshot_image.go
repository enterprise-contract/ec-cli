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

package application_snapshot_image

import (
	"bytes"
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
	"github.com/qri-io/jsonschema"
	app "github.com/redhat-appstudio/application-api/api/v1alpha1"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/enterprise-contract/ec-cli/internal/attestation"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/fetchers/oci/config"
	"github.com/enterprise-contract/ec-cli/internal/fetchers/oci/files"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/signature"
	"github.com/enterprise-contract/ec-cli/internal/utils"
	"github.com/enterprise-contract/ec-cli/pkg/schema"
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
	reference        name.Reference
	checkOpts        cosign.CheckOpts
	signatures       []signature.EntitySignature
	configJSON       json.RawMessage
	parentConfigJSON json.RawMessage
	parentRef        name.Reference
	attestations     []attestation.Attestation
	Evaluators       []evaluator.Evaluator
	files            map[string]json.RawMessage
	component        app.SnapshotComponent
}

func (a ApplicationSnapshotImage) GetReference() name.Reference {
	return a.reference
}

// NewApplicationSnapshotImage returns an ApplicationSnapshotImage struct with reference, checkOpts, and evaluator ready to use.
func NewApplicationSnapshotImage(ctx context.Context, component app.SnapshotComponent, p policy.Policy) (*ApplicationSnapshotImage, error) {
	opts, err := p.CheckOpts()
	if err != nil {
		return nil, err
	}
	a := &ApplicationSnapshotImage{
		checkOpts: *opts,
		component: component,
	}

	if err := a.SetImageURL(component.ContainerImage); err != nil {
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

		c, err := newConftestEvaluator(ctx, policySources, p, sourceGroup)
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
	a.attestations = []attestation.Attestation{}
	a.signatures = []signature.EntitySignature{}

	return nil
}

func (a *ApplicationSnapshotImage) FetchImageConfig(ctx context.Context) error {
	opts := []remote.Option{
		imageRefTransport,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}
	var err error
	a.configJSON, err = config.FetchImageConfig(ctx, a.reference, opts...)
	return err
}

func (a *ApplicationSnapshotImage) FetchParentImageConfig(ctx context.Context) error {
	opts := []remote.Option{
		imageRefTransport,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}

	var err error
	a.parentRef, err = config.FetchParentImage(ctx, a.reference, opts...)
	if err != nil {
		return err
	}
	a.parentConfigJSON, err = config.FetchImageConfig(ctx, a.parentRef, opts...)
	return err
}

func (a *ApplicationSnapshotImage) FetchImageFiles(ctx context.Context) error {
	opts := []remote.Option{
		imageRefTransport,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}
	var err error
	a.files, err = files.ImageFiles(ctx, a.reference, opts...)
	return err
}

// use NewClient(ctx) for all of these
func (a *ApplicationSnapshotImage) FetchDigest() (name.Digest, error) {
	digest, err := ociremote.ResolveDigest(a.reference, a.checkOpts.RegistryClientOpts...)
	if err != nil {
		return digest, err
	}
	return digest, nil
}

// ValidateImageSignature executes the cosign.VerifyImageSignature method on the ApplicationSnapshotImage image ref.
func (a *ApplicationSnapshotImage) ValidateImageSignature(ctx context.Context) error {
	// Set the ClaimVerifier on a shallow *copy* of CheckOpts to avoid unexpected side-effects
	opts := a.checkOpts
	opts.ClaimVerifier = cosign.SimpleClaimVerifier
	signatures, _, err := NewClient(ctx).VerifyImageSignatures(ctx, a.reference, &opts)
	if err != nil {
		return err
	}

	for _, s := range signatures {
		es, err := signature.NewEntitySignature(s)
		if err != nil {
			return err
		}
		a.signatures = append(a.signatures, es)
	}

	return nil
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
	for _, sig := range layers {
		att, err := attestation.ProvenanceFromSignature(sig)
		if err != nil {
			return fmt.Errorf("unable to parse untyped provenance: %w", err)
		}
		t := att.PredicateType()
		log.Debugf("Found attestation with predicateType: %s", t)
		switch t {
		case attestation.PredicateSLSAProvenance:
			// SLSAProvenanceFromSignature does the payload extraction
			// and decoding that was done in ProvenanceFromSignature
			// over again. We could refactor so we're not doing that twice,
			// but it's not super important IMO.
			sp, err := attestation.SLSAProvenanceFromSignature(sig)

			if err != nil {
				return fmt.Errorf("unable to parse as SLSA v0.2: %w", err)
			}
			a.attestations = append(a.attestations, sp)

		case attestation.PredicateSpdxDocument:
			// It's an SPDX format SBOM
			// Todo maybe: We could unmarshal it into a suitable SPDX struct
			// similar to how it's done for SLSA above
			a.attestations = append(a.attestations, att)

		// Todo: CycloneDX format SBOM

		default:
			// It's some other kind of attestation
			a.attestations = append(a.attestations, att)
		}
	}
	return nil
}

// ValidateAttestationSyntax validates the attestations against known JSON
// schemas, errors out if there are no attestations to check to prevent
// successful syntax check of no inputs, must invoke
// [ValidateAttestationSignature] to prefill the attestations.
func (a ApplicationSnapshotImage) ValidateAttestationSyntax(ctx context.Context) error {
	if len(a.attestations) == 0 {
		log.Debug("No attestation data found, possibly due to attestation image signature not being validated beforehand")
		return errors.New("no attestation data")
	}

	allErrors := map[string][]jsonschema.KeyError{}
	for _, sp := range a.attestations {
		pt := sp.PredicateType()
		if schema, ok := attestationSchemas[pt]; ok {
			// Found a validator for this predicate type so let's use it
			log.Debugf("Attempting to validate an attestation with predicateType %s", pt)
			if errs, err := schema.ValidateBytes(ctx, sp.Statement()); err != nil {
				// Error while trying to validate
				return fmt.Errorf("unable to decode attestation data from attestation image: %w", err)
			} else {
				if len(errs) == 0 {
					log.Debugf("Statement schema was validated successfully against the %s schema", pt)
				} else {
					log.Debugf("Validated the statement against %s schema and found the following errors: %v", pt, errs)
					allErrors[pt] = errs
				}
			}
		} else {
			log.Debugf("No schema validation found for predicateType %s", pt)
		}
	}

	if len(allErrors) == 0 {
		// TODO another option might be to filter out invalid statement JSONs
		// and keep only the valid ones
		return nil
	}

	log.Debug("Failed to validate statements from the attestation image against all known schemas")
	msg := ""
	for id, errs := range allErrors {
		msg += fmt.Sprintf("\nSchema ID: %s", id)
		for _, e := range errs {
			msg += fmt.Sprintf("\n - %s", e.Error())
		}
	}
	return fmt.Errorf("attestation syntax validation failed: %s", msg)
}

// Attestations returns the value of the attestations field of the ApplicationSnapshotImage struct
func (a *ApplicationSnapshotImage) Attestations() []attestation.Attestation {
	return a.attestations
}

func (a *ApplicationSnapshotImage) Signatures() []signature.EntitySignature {
	return a.signatures
}

func (a *ApplicationSnapshotImage) ResolveDigest(ctx context.Context) (string, error) {
	digest, err := NewClient(ctx).ResolveDigest(a.reference, &a.checkOpts)
	if err != nil {
		return "", err
	}
	return digest, nil
}

type attestationData struct {
	Statement  json.RawMessage             `json:"statement"`
	Signatures []signature.EntitySignature `json:"signatures,omitempty"`
}

// MarshalJSON returns a JSON representation of the attestationData. It is customized to take into
// account that attestationData extends json.RawMessage. Leveraging the underlying MarshalJSON from
// json.RawMessage is problematic because its implementation excludes the additional attributes in
// attestationData. Instead, this method assumes the data being represented is a JSON object and it
// adds the additional attributes to it. Once the deprecated options of attestationData are removed,
// a standard process for Marshaling the JSON can be used, thus removing the need for this method.
func (a attestationData) MarshalJSON() ([]byte, error) {
	buffy := bytes.Buffer{}

	_, err := buffy.WriteString(`{"statement":`)
	if err != nil {
		return nil, fmt.Errorf("write statement key: %w", err)
	}
	statement, err := a.Statement.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal json statement: %w", err)
	}
	if _, err := buffy.Write(statement); err != nil {
		return nil, fmt.Errorf("write statement value: %w", err)
	}

	if len(a.Signatures) > 0 {
		_, err = buffy.WriteString(`, "signatures":`)
		if err != nil {
			return nil, fmt.Errorf("write signatures key: %w", err)
		}
		signatures, err := json.Marshal(a.Signatures)
		if err != nil {
			return nil, fmt.Errorf("marshal json signatures: %w", err)
		}
		if _, err := buffy.Write(signatures); err != nil {
			return nil, fmt.Errorf("write signatues value: %w", err)
		}
	}

	if err := buffy.WriteByte('}'); err != nil {
		return nil, fmt.Errorf("close json: %w", err)
	}

	return buffy.Bytes(), nil
}

type image struct {
	Ref        string                      `json:"ref"`
	Signatures []signature.EntitySignature `json:"signatures,omitempty"`
	Config     json.RawMessage             `json:"config,omitempty"`
	Parent     any                         `json:"parent,omitempty"`
	Files      map[string]json.RawMessage  `json:"files,omitempty"`
	Source     any                         `json:"source,omitempty"`
}

type Input struct {
	Attestations []attestationData `json:"attestations"`
	Image        image             `json:"image"`
}

// WriteInputFile writes the JSON from the attestations to input.json in a random temp dir
func (a *ApplicationSnapshotImage) WriteInputFile(ctx context.Context) (string, []byte, error) {
	log.Debugf("Attempting to write %d attestations to input file", len(a.attestations))

	var attestations []attestationData
	for _, a := range a.attestations {
		attestations = append(attestations, attestationData{
			Statement:  a.Statement(),
			Signatures: a.Signatures(),
		})
	}

	input := Input{
		Attestations: attestations,
		Image: image{
			Ref:        a.reference.String(),
			Signatures: a.signatures,
			Config:     a.configJSON,
			Files:      a.files,
			Source:     a.component.Source,
		},
	}

	if a.parentRef != nil {
		input.Image.Parent = image{
			Ref:    a.parentRef.String(),
			Config: a.parentConfigJSON,
		}
	}

	fs := utils.FS(ctx)
	inputDir, err := afero.TempDir(fs, "", "ecp_input.")
	if err != nil {
		log.Debug("Problem making temp dir!")
		return "", nil, err
	}
	log.Debugf("Created dir %s", inputDir)
	inputJSONPath := path.Join(inputDir, "input.json")

	f, err := fs.OpenFile(inputJSONPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0644)
	if err != nil {
		log.Debugf("Problem creating file in %s", inputDir)
		return "", nil, err
	}
	defer f.Close()

	inputJSON, err := json.Marshal(input)
	if err != nil {
		return "", nil, fmt.Errorf("input to JSON: %w", err)
	}

	if _, err := f.Write(inputJSON); err != nil {
		return "", nil, fmt.Errorf("write input to file: %w", err)
	}

	log.Debugf("Done preparing input file:\n%s", inputJSONPath)
	return inputJSONPath, inputJSON, nil
}
