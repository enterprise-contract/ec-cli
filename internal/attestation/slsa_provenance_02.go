// Copyright 2023 Red Hat, Inc.
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

package attestation

import (
	"encoding/base64"
	"encoding/json"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/types"

	"github.com/enterprise-contract/ec-cli/internal/output"
)

// SLSAProvenanceFromLayer parses the SLSA Provenance v0.2 from the provided OCI
// layer. Expects that the layer contains DSSE JSON with the embeded SLSA
// Provenance v0.2 payload.
func SLSAProvenanceFromLayer(layer v1.Layer) (Attestation[in_toto.ProvenanceStatementSLSA02], error) {
	if layer == nil {
		return nil, AT001
	}
	typ, err := layer.MediaType()
	if err != nil {
		return nil, AT002.CausedBy(err)
	}

	if typ != types.DssePayloadType {
		return nil, AT002.CausedByF("Expecting media type of `%s`, received: `%s`", types.DssePayloadType, typ)
	}

	reader, err := layer.Uncompressed()
	if err != nil {
		return nil, AT002.CausedBy(err)
	}
	defer reader.Close()

	payloadBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, AT002.CausedBy(err)
	}

	var payload cosign.AttestationPayload
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return nil, AT002.CausedBy(err)
	}

	if payload.PayLoad == "" {
		return nil, AT002.CausedByF("No `payload` data found")
	}

	embeded, err := base64.StdEncoding.DecodeString(payload.PayLoad)
	if err != nil {
		return nil, AT002.CausedBy(err)
	}

	var statement in_toto.ProvenanceStatementSLSA02
	if err := json.Unmarshal(embeded, &statement); err != nil {
		return nil, AT002.CausedBy(err)
	}

	if statement.Type != in_toto.StatementInTotoV01 {
		return nil, AT003.CausedByF(statement.Type)
	}

	if statement.PredicateType != v02.PredicateSLSAProvenance {
		return nil, AT004.CausedByF(statement.PredicateType)
	}

	return slsaProvenance{statement: statement, payload: payload, bytes: embeded}, nil
}

type slsaProvenance struct {
	statement in_toto.ProvenanceStatementSLSA02
	payload   cosign.AttestationPayload
	bytes     []byte
}

func (a slsaProvenance) Data() []byte {
	return a.bytes
}

func (a slsaProvenance) Statement() in_toto.ProvenanceStatementSLSA02 {
	return a.statement
}

func (a slsaProvenance) Signatures() []output.EntitySignature {
	metadata := describeStatement(a.statement)

	var sigs []output.EntitySignature
	for _, sig := range a.payload.Signatures {
		sigs = append(sigs, output.EntitySignature{
			KeyID:     sig.KeyID,
			Signature: sig.Sig,
			Metadata:  metadata,
		})
	}

	return sigs
}

func describeStatement(statement in_toto.ProvenanceStatementSLSA02) map[string]string {
	description := map[string]string{
		"predicateType": statement.PredicateType,
		"type":          statement.Type,
	}

	if statement.Predicate.BuildType != "" {
		description["predicateBuildType"] = statement.Predicate.BuildType
	}

	return description
}
