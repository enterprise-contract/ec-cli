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
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	log "github.com/sirupsen/logrus"

	"github.com/hacbs-contract/ec-cli/internal/output"
)

func entitySignatureFromAttestation(att oci.Signature) ([]output.EntitySignature, error) {
	payload, err := att.Payload()
	if err != nil {
		return nil, fmt.Errorf("fetch attestation payload: %w", err)
	}

	var attestationPayload cosign.AttestationPayload
	if err := json.Unmarshal(payload, &attestationPayload); err != nil {
		return nil, fmt.Errorf("unmarshal attestation payload: %w", err)
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(attestationPayload.PayLoad)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var statement in_toto.Statement
	if err := json.Unmarshal(decodedPayload, &statement); err != nil {
		return nil, fmt.Errorf("unmarshal in-toto statement: %w", err)
	}

	predicateURI := slsa.PredicateSLSAProvenance
	if statement.PredicateType != predicateURI {
		log.Debugf("Skipping attestation; want %q, got %q", predicateURI, statement.PredicateType)
		return nil, nil
	}

	metadata, err := describeStatement(statement)
	if err != nil {
		return nil, err
	}

	var sigs []output.EntitySignature
	for _, sig := range attestationPayload.Signatures {
		sigs = append(sigs, output.EntitySignature{
			KeyID:     sig.KeyID,
			Signature: sig.Sig,
			Metadata:  metadata,
		})
	}

	return sigs, nil
}

func describeStatement(statement in_toto.Statement) (map[string]string, error) {
	description := map[string]string{
		"predicateType": statement.PredicateType,
		"type":          statement.Type,
	}

	if predicate, ok := statement.Predicate.(map[string]interface{}); ok {
		if buildType, ok := predicate["buildType"].(string); ok && len(buildType) > 0 {
			description["predicateBuildType"] = buildType
		}
	}

	return description, nil
}
