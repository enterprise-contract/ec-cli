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

	"github.com/google/go-containerregistry/pkg/name"
	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/policy"
	"github.com/sigstore/cosign/pkg/signature"
	cosignTypes "github.com/sigstore/cosign/pkg/types"
	log "github.com/sirupsen/logrus"

	"github.com/hacbs-contract/ec-cli/internal/evaluator"
	"github.com/hacbs-contract/ec-cli/internal/kubernetes"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
)

// ConftestNamespace is the default rego namespace using for policy evaluation
const ConftestNamespace = "release.main"

// PipelineRunBuildType is the type of attestation we're interested in evaluating
const PipelineRunBuildType = "https://tekton.dev/attestations/chains/pipelinerun@v2"

var newConftestEvaluator = evaluator.NewConftestEvaluator
var kubernetesClientCreator = kubernetes.NewClient

// ApplicationSnapshotImage represents the structure needed to evaluate an Application Snapshot Image
type ApplicationSnapshotImage struct {
	reference    name.Reference
	checkOpts    cosign.CheckOpts
	attestations []oci.Signature
	Evaluator    *evaluator.ConftestEvaluator
}

// NewApplicationSnapshotImage returns an ApplicationSnapshotImage struct with reference, checkOpts, and evaluator ready to use.
func NewApplicationSnapshotImage(ctx context.Context, image string, publicKey string, rekorURL string, policyConfiguration string) (*ApplicationSnapshotImage, error) {
	if len(policyConfiguration) == 0 {
		return nil, fmt.Errorf("policy: policy name is required")
	}
	log.Debugf("Raw policy name %s", policyConfiguration)

	policyName, err := kubernetes.NamespacedName(policyConfiguration)
	if err != nil {
		return nil, err
	}
	log.Debugf("Parsed policy name %s", policyName)

	ref, err := name.ParseReference(image)
	if err != nil {
		log.Debugf("Failed to parse reference %s", image)
		return nil, err
	}
	log.Debugf("Parsed reference %s", ref)

	checkOpts, err := getCheckOpts(ctx, publicKey, rekorURL)
	if err != nil {
		return nil, err
	}

	a := &ApplicationSnapshotImage{
		reference: ref,
		checkOpts: checkOpts,
	}

	k8s, err := kubernetesClientCreator()
	if err != nil {
		log.Debug("Failed to initialize Kubernetes client")
		return nil, err
	}

	ecp, err := k8s.FetchEnterpriseContractPolicy(ctx, *policyName)
	if err != nil {
		log.Debug("Failed to fetch the enterprise contract policy from the cluster!")
		return nil, err
	}
	log.Debug("Enterprise contract policy fetched from cluster")

	policies, err := fetchPolicyRepos(ecp.Spec)
	if err != nil {
		log.Debug("Failed to fetch the policy repos from the ECP!")
		return nil, err
	}
	log.Debug("Policy repos fetched")
	for _, policyRepo := range policies {
		policyRepoJson, _ := json.Marshal(policyRepo)
		log.Debugf("%s", policyRepoJson)
	}

	c, err := newConftestEvaluator(ctx, policies, []string{ConftestNamespace})
	if err != nil {
		log.Debug("Failed to initialize the conftest evaluator!")
		return nil, err
	}
	log.Debug("Conftest evaluator initialized")
	a.Evaluator = c
	return a, nil
}

// getCheckOpts returns a cosign.CheckOpts struct
func getCheckOpts(ctx context.Context, publicKey string, rekorURL string) (cosign.CheckOpts, error) {
	verifier, err := signature.PublicKeyFromKeyRef(ctx, publicKey)
	if err != nil {
		log.Debugf("Problem creating signature verifier using public key %s", publicKey)
		return cosign.CheckOpts{}, err
	}

	checkOpts := cosign.CheckOpts{}
	checkOpts.SigVerifier = verifier
	log.Debugf("Signature verifier created using public key %s", publicKey)

	if len(rekorURL) > 0 {
		rekorClient, err := rekor.NewClient(rekorURL)
		if err != nil {
			log.Debug("Problem creating a rekor client")
			return cosign.CheckOpts{}, err
		}

		checkOpts.RekorClient = rekorClient
		log.Debug("Rekor client created")
	}
	return checkOpts, nil
}

// fetchPolicyRepos returns an array of Policy repos
func fetchPolicyRepos(spec ecc.EnterpriseContractPolicySpec) ([]source.PolicySource, error) {
	policySources := make([]source.PolicySource, 0, len(spec.Sources))
	for _, policySource := range spec.Sources {
		if policySource.GitRepository != nil {
			repo, err := source.CreatePolicyRepoFromSource(*policySource.GitRepository)
			if err != nil {
				return nil, err
			}
			policySources = append(policySources, &repo)
		}
	}
	return policySources, nil
}

// ValidateImageSignature executes the cosign.VerifyImageSignature method on the ApplicationSnapshotImage image ref.
func (a *ApplicationSnapshotImage) ValidateImageSignature() error {
	_, _, err := cosign.VerifyImageSignatures(a.Evaluator.Context, a.reference, &a.checkOpts)
	return err
}

// ValidateAttestationSignature executes the cosign.VerifyImageAttestations method
func (a *ApplicationSnapshotImage) ValidateAttestationSignature() error {
	attestations, _, err := cosign.VerifyImageAttestations(a.Evaluator.Context, a.reference, &a.checkOpts)
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
func (a *ApplicationSnapshotImage) WriteInputFiles() ([]string, error) {
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
		payload, err := policy.AttestationToPayloadJSON(a.Evaluator.Context, "slsaprovenance", att)
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

		inputDir, err := os.MkdirTemp("", "ecp_input.*")
		if err != nil {
			log.Debug("Problem making temp dir!")
			return nil, err
		}
		log.Debugf("Created dir %s", inputDir)
		inputJSONPath := path.Join(inputDir, "input.json")
		input, err := os.Create(inputJSONPath)
		if err != nil {
			log.Debugf("Problem creating file in %s", inputDir)
			return nil, err
		}
		log.Debugf("Created json file in %s", inputDir)
		defer input.Close()

		fmt.Fprint(input, `{"attestations":[`)
		j := json.NewEncoder(input)
		err = j.Encode(statement)
		if err != nil {
			log.Debug("Problem encoding attestion json!")
			return nil, err
		}
		fmt.Fprint(input, `]}`)

		inputs = append(inputs, inputJSONPath)

	}

	log.Debugf("Done preparing inputs:\n%s", inputs)
	return inputs, nil
}
