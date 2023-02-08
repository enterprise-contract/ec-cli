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

//go:build unit

package application_snapshot_image

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/hacbs-contract/ec-cli/internal/output"
)

func TestEntitySignatureFromAttestation(t *testing.T) {
	cases := []struct {
		name       string
		signature  *mockSignature
		setup      func(*mockSignature)
		signatures []output.EntitySignature
		err        string
	}{
		{
			name:      "payload error",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				m.On("Payload").Return([]byte{}, errors.New("kaboom!"))
			},
			err: "fetch attestation payload: kaboom!",
		},
		{
			name:      "invalid attestation payload JSON",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				payload := fmt.Sprintf(`{"signatures": [%s]}}}}}`, sig1)
				m.On("Payload").Return([]byte(payload), nil)
			},
			err: "unmarshal attestation payload: invalid character '}' after top-level value",
		},
		{
			name:      "invalid statement JSON",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				provenancePayload := "not-base64"
				payload := fmt.Sprintf(`{"signatures": [%s], "payload": "`+provenancePayload+`"}`, sig1)
				m.On("Payload").Return([]byte(payload), nil)
			},
			err: "decode payload: illegal base64 data at input byte 3",
		},
		{
			name:      "invalid statement JSON",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				provenancePayload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType":"https://slsa.dev/provenance/v0.2",
					"predicate":{} }}}}}}}}}
				}`)
				payload := fmt.Sprintf(`{"signatures": [%s], "payload": "`+provenancePayload+`"}`, sig1)
				m.On("Payload").Return([]byte(payload), nil)
			},
			err: "unmarshal in-toto statement: invalid character '}' after top-level value",
		},
		{
			name:      "ignore unexpected predicate type",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				provenancePayload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType":"kaboom"
				}`)
				payload := fmt.Sprintf(`{"signatures": [%s], "payload": "`+provenancePayload+`"}`, sig1)
				m.On("Payload").Return([]byte(payload), nil)
			},
		},
		{
			name:      "missing signatures",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				provenancePayload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType":"https://slsa.dev/provenance/v0.2",
					"predicate":{"buildType":"` + pipelineRunBuildType + `"}
				}`)
				payload := fmt.Sprintf(`{"signatures": [], "payload": "` + provenancePayload + `"}`)
				m.On("Payload").Return([]byte(payload), nil)
			},
		},
		{
			name:      "valid",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				sig2 := `{"keyid": "key-id-2", "sig": "sig-2"}`
				provenancePayload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType":"https://slsa.dev/provenance/v0.2",
					"predicate":{"buildType":"` + pipelineRunBuildType + `"}
				}`)
				payload := fmt.Sprintf(`{"signatures": [%s, %s], "payload": "`+provenancePayload+`"}`, sig1, sig2)
				m.On("Payload").Return([]byte(payload), nil)
			},
			signatures: []output.EntitySignature{
				{KeyID: "key-id-1", Signature: "sig-1", Metadata: map[string]string{
					"type":               "https://in-toto.io/Statement/v0.1",
					"predicateBuildType": "https://tekton.dev/attestations/chains/pipelinerun@v2",
					"predicateType":      "https://slsa.dev/provenance/v0.2",
				}},
				{KeyID: "key-id-2", Signature: "sig-2", Metadata: map[string]string{
					"type":               "https://in-toto.io/Statement/v0.1",
					"predicateBuildType": "https://tekton.dev/attestations/chains/pipelinerun@v2",
					"predicateType":      "https://slsa.dev/provenance/v0.2",
				}},
			},
		},
		{
			name:      "valid, but missing buildType",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				sig2 := `{"keyid": "key-id-2", "sig": "sig-2"}`
				provenancePayload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType":"https://slsa.dev/provenance/v0.2",
					"predicate":{}
				}`)
				payload := fmt.Sprintf(`{"signatures": [%s, %s], "payload": "`+provenancePayload+`"}`, sig1, sig2)
				m.On("Payload").Return([]byte(payload), nil)
			},
			signatures: []output.EntitySignature{
				{KeyID: "key-id-1", Signature: "sig-1", Metadata: map[string]string{
					"type":          "https://in-toto.io/Statement/v0.1",
					"predicateType": "https://slsa.dev/provenance/v0.2",
				}},
				{KeyID: "key-id-2", Signature: "sig-2", Metadata: map[string]string{
					"type":          "https://in-toto.io/Statement/v0.1",
					"predicateType": "https://slsa.dev/provenance/v0.2",
				}},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.setup != nil {
				c.setup(c.signature)
			}
			signatures, err := entitySignatureFromAttestation(c.signature)
			if c.err != "" {
				assert.EqualError(t, err, c.err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, c.signatures, signatures)
		})
	}
}

func encode(payload string) string {
	return base64.StdEncoding.EncodeToString([]byte(payload))
}
