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
	"os"
	"path"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	cosignPolicy "github.com/sigstore/cosign/pkg/policy"
	cosignTypes "github.com/sigstore/cosign/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/hacbs-contract/ec-cli/internal/evaluator"
	"github.com/hacbs-contract/ec-cli/internal/policy"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
)

// ConftestNamespace is the default rego namespace using for policy evaluation
const ConftestNamespace = "release.main"

// PipelineRunBuildType is the type of attestation we're interested in evaluating
const PipelineRunBuildType = "https://tekton.dev/attestations/chains/pipelinerun@v2"

var newConftestEvaluator = evaluator.NewConftestEvaluator

// imageRefTransport is used to inject the type of transport to use with the
// remote.WithTransport function. By default, remote.DefaultTransport is
// equivalent to http.DefaultTransport, with a reduced timeout and keep-alive
var imageRefTransport = remote.WithTransport(remote.DefaultTransport)

// ApplicationSnapshotImage represents the structure needed to evaluate an Application Snapshot Image
type ApplicationSnapshotImage struct {
	reference    name.Reference
	checkOpts    cosign.CheckOpts
	attestations []oci.Signature
	Evaluator    evaluator.Evaluator
}

// NewApplicationSnapshotImage returns an ApplicationSnapshotImage struct with reference, checkOpts, and evaluator ready to use.
func NewApplicationSnapshotImage(ctx context.Context, fs afero.Fs, image string, ecp *ecc.EnterpriseContractPolicySpec) (*ApplicationSnapshotImage, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		log.Debugf("Failed to parse reference %s", image)
		return nil, err
	}
	log.Debugf("Parsed reference %s", ref)

	checkOpts, err := policy.CheckOpts(ctx, ecp)
	if err != nil {
		return nil, err
	}

	if checkOpts.RekorClient != nil {
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

	a := &ApplicationSnapshotImage{
		reference: ref,
		checkOpts: *checkOpts,
	}

	policySources, err := fetchPolicySources(ecp)
	if err != nil {
		log.Debug("Failed to fetch the policy sources from the ECP!")
		return nil, err
	}

	log.Debug("Policy source definitions fetched")
	for _, policySource := range policySources {
		policySourceJson, _ := json.Marshal(policySource)
		log.Debugf("policySourceJson: %s", policySourceJson)
	}

	c, err := newConftestEvaluator(ctx, fs, policySources, ConftestNamespace, ecp)
	if err != nil {
		log.Debug("Failed to initialize the conftest evaluator!")
		return nil, err
	}
	log.Debug("Conftest evaluator initialized")
	a.Evaluator = c
	return a, nil
}

// fetchPolicySources returns an array of policy sources
func fetchPolicySources(spec *ecc.EnterpriseContractPolicySpec) ([]source.PolicySource, error) {
	policySources := make([]source.PolicySource, 0, len(spec.Sources))
	for _, sourceUrl := range spec.Sources {
		url := source.PolicyUrl(sourceUrl)
		policySources = append(policySources, &url)
	}
	return policySources, nil
}

// ValidateImageAccess executes the remote.Head method on the ApplicationSnapshotImage image ref
func (a *ApplicationSnapshotImage) ValidateImageAccess(ctx context.Context) error {
	resp, err := remote.Head(a.reference, imageRefTransport, remote.WithContext(ctx))
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("no response received")
	}
	log.Debugf("Resp: %+v", resp)
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
	return nil
}

// Attestations returns the value of the attestations field of the ApplicationSnapshotImage struct
func (a *ApplicationSnapshotImage) Attestations() []oci.Signature {
	return a.attestations
}

// WriteInputFiles writes the JSON from the attestations to input.json in a random temp dir
func (a *ApplicationSnapshotImage) WriteInputFiles(ctx context.Context, fs afero.Fs) ([]string, error) {
	attCount := len(a.attestations)
	log.Debugf("Attempting to write %d attestations to inputs", attCount)
	inputs := make([]string, 0, attCount)

	for _, att := range a.attestations {
		typ, err := att.MediaType()
		if err != nil {
			log.Debug("Problem finding media type!")
			return nil, err
		}

		if typ != cosignTypes.DssePayloadType {
			log.Debugf("Skipping unexpected media type %s", typ)
			continue
		}
		payload, err := cosignPolicy.AttestationToPayloadJSON(ctx, "slsaprovenance", att)
		if err != nil {
			log.Debug("Problem extracting json payload from attestation!")
			return nil, err
		}

		var statement in_toto.Statement
		err = json.Unmarshal(payload, &statement)
		if err != nil {
			log.Debug("Problem parsing attestation payload json!")
			return nil, err
		}

		predicates, ok := statement.Predicate.(map[string]interface{})
		if !ok {
			log.Debug("Unexpected attestation payload format!")
			return nil, errors.New("expecting map with string keys in in-toto Statement, did not find it")
		}

		if predicates["buildType"] != PipelineRunBuildType {
			log.Debugf("Skipping attestation with unexpected predicate buildType '%s'", predicates["buildType"])
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
				statement,
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
