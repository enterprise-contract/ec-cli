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
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	ct "github.com/sigstore/cosign/v2/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/hacbs-contract/ec-cli/internal/output"
	e "github.com/hacbs-contract/ec-cli/pkg/error"
)

type mockLayer struct {
	*mock.Mock
}

func (l mockLayer) Digest() (v1.Hash, error) {
	args := l.Called()

	return args.Get(0).(v1.Hash), args.Error(1)
}

func (l mockLayer) DiffID() (v1.Hash, error) {
	args := l.Called()

	return args.Get(0).(v1.Hash), args.Error(1)
}

func (l mockLayer) Compressed() (io.ReadCloser, error) {
	args := l.Called()

	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (l mockLayer) Uncompressed() (io.ReadCloser, error) {
	args := l.Called()

	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (l mockLayer) Size() (int64, error) {
	args := l.Called()

	return args.Get(0).(int64), args.Error(1)
}

func (l mockLayer) MediaType() (types.MediaType, error) {
	args := l.Called()

	return args.Get(0).(types.MediaType), args.Error(1)
}

func TestSLSAProvenanceFromLayerNilLayer(t *testing.T) {
	sp, err := SLSAProvenanceFromLayer(nil)
	assert.True(t, AT001.Alike(err), "Expecting `%v` to be alike: `%v`", err, AT001)
	assert.Nil(t, sp)
}

func TestSLSAProvenanceFromLayer(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(l *mockLayer)
		data      string
		statement in_toto.ProvenanceStatementSLSA02
		err       e.Error
	}{
		{
			name: "media type error",
			setup: func(l *mockLayer) {
				l.On("MediaType").Return(types.MediaType(""), errors.New("expected"))
			},
			err: AT002.CausedByF("expected"),
		},
		{
			name: "no media type",
			setup: func(l *mockLayer) {
				l.On("MediaType").Return(types.MediaType(""), nil)
			},
			err: AT002.CausedByF("Expecting media type of `application/vnd.dsse.envelope.v1+json`, received: ``"),
		},
		{
			name: "unsupported media type",
			setup: func(l *mockLayer) {
				l.On("MediaType").Return(types.MediaType("xxx"), nil)
			},
			err: AT002.CausedByF("Expecting media type of `application/vnd.dsse.envelope.v1+json`, received: `xxx`"),
		},
		{
			name: "no payload JSON",
			setup: func(l *mockLayer) {
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(io.NopCloser(&bytes.Buffer{}), nil)
			},
			err: AT002.CausedByF("unexpected end of JSON input"),
		},
		{
			name: "empty payload JSON",
			data: "{}",
			setup: func(l *mockLayer) {
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(`{"payload":"`+base64.StdEncoding.EncodeToString([]byte("{}"))+`"}`), nil)
			},
			err: AT003.CausedByF(""),
		},
		{
			name: "invalid attestation payload JSON",
			setup: func(l *mockLayer) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				payload := fmt.Sprintf(`{"signatures": [%s]}}}}}`, sig1)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(payload), nil)
			},
			err: AT002.CausedByF("invalid character '}' after top-level value"),
		},
		{
			name: "invalid statement JSON",
			setup: func(l *mockLayer) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				provenancePayload := "not-base64"
				payload := fmt.Sprintf(`{"signatures": [%s], "payload": "`+provenancePayload+`"}`, sig1)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(payload), nil)
			},
			err: AT002.CausedByF("illegal base64 data at input byte 3"),
		},
		{
			name: "invalid statement JSON",
			setup: func(l *mockLayer) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				provenancePayload := encode(`{
						"_type": "https://in-toto.io/Statement/v0.1",
						"predicateType":"https://slsa.dev/provenance/v0.2",
						"predicate":{} }}}}}}}}}
					}`)
				payload := fmt.Sprintf(`{"signatures": [%s], "payload": "`+provenancePayload+`"}`, sig1)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(payload), nil)
			},
			err: AT002.CausedByF("invalid character '}' after top-level value"),
		},
		{
			name: "unexpected predicate type",
			setup: func(l *mockLayer) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				provenancePayload := encode(`{
						"_type": "https://in-toto.io/Statement/v0.1",
						"predicateType":"kaboom"
					}`)
				payload := fmt.Sprintf(`{"signatures": [%s], "payload": "`+provenancePayload+`"}`, sig1)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(payload), nil)
			},
			err: AT004.CausedByF("kaboom"),
		},
		{
			name: "valid",
			data: `{"_type":"https://in-toto.io/Statement/v0.1", "predicateType":"https://slsa.dev/provenance/v0.2","predicate":{"buildType":"https://my.build.type"}}`,
			setup: func(l *mockLayer) {
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(`{"payload":"`+base64.StdEncoding.EncodeToString([]byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","predicate":{"buildType":"https://my.build.type"}}`))+`"}`), nil)
			},
			statement: in_toto.ProvenanceStatementSLSA02{
				StatementHeader: in_toto.StatementHeader{
					Type:          in_toto.StatementInTotoV01,
					PredicateType: v02.PredicateSLSAProvenance,
				},
				Predicate: v02.ProvenancePredicate{
					BuildType: "https://my.build.type",
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			layer := mockLayer{&mock.Mock{}}

			if c.setup != nil {
				c.setup(&layer)
			}

			sp, err := SLSAProvenanceFromLayer(layer)
			if c.err == nil {
				require.Nil(t, err)
				require.NotNil(t, sp)
			} else {
				require.Nil(t, sp)
				assert.True(t, c.err.Alike(err), "Expecting `%v` to be alike: `%v`", err, c.err)
				return
			}

			if c.data == "" {
				assert.Nil(t, sp.Data())
			} else {
				assert.JSONEq(t, c.data, string(sp.Data()))
			}
			assert.Equal(t, c.statement, sp.Statement())
		})
	}
}

func TestEntitySignature(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(l *mockLayer)
		signatures []output.EntitySignature
		err        e.Error
	}{
		{
			name: "missing signatures",
			setup: func(l *mockLayer) {
				provenancePayload := encode(`{
						"_type": "https://in-toto.io/Statement/v0.1",
						"predicateType":"https://slsa.dev/provenance/v0.2"
					}`)
				payload := fmt.Sprintf(`{"signatures": [], "payload": "` + provenancePayload + `"}`)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(payload), nil)
			},
		},
		{
			name: "valid",
			setup: func(l *mockLayer) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				sig2 := `{"keyid": "key-id-2", "sig": "sig-2"}`
				provenancePayload := encode(`{
						"_type": "https://in-toto.io/Statement/v0.1",
						"predicateType":"https://slsa.dev/provenance/v0.2",
						"predicate":{"buildType":"https://my.build.type"}
					}`)
				payload := fmt.Sprintf(`{"signatures": [%s, %s], "payload": "`+provenancePayload+`"}`, sig1, sig2)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(payload), nil)
			},
			signatures: []output.EntitySignature{
				{KeyID: "key-id-1", Signature: "sig-1", Metadata: map[string]string{
					"type":               "https://in-toto.io/Statement/v0.1",
					"predicateBuildType": "https://my.build.type",
					"predicateType":      "https://slsa.dev/provenance/v0.2",
				}},
				{KeyID: "key-id-2", Signature: "sig-2", Metadata: map[string]string{
					"type":               "https://in-toto.io/Statement/v0.1",
					"predicateBuildType": "https://my.build.type",
					"predicateType":      "https://slsa.dev/provenance/v0.2",
				}},
			},
		},
		{
			name: "valid, but missing buildType",
			setup: func(l *mockLayer) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				sig2 := `{"keyid": "key-id-2", "sig": "sig-2"}`
				provenancePayload := encode(`{
						"_type": "https://in-toto.io/Statement/v0.1",
						"predicateType":"https://slsa.dev/provenance/v0.2",
						"predicate":{}
					}`)
				payload := fmt.Sprintf(`{"signatures": [%s, %s], "payload": "`+provenancePayload+`"}`, sig1, sig2)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(payload), nil)
			},
			signatures: []output.EntitySignature{
				{KeyID: "key-id-1", Signature: "sig-1", Metadata: map[string]string{
					"type":          in_toto.StatementInTotoV01,
					"predicateType": v02.PredicateSLSAProvenance,
				}},
				{KeyID: "key-id-2", Signature: "sig-2", Metadata: map[string]string{
					"type":          in_toto.StatementInTotoV01,
					"predicateType": v02.PredicateSLSAProvenance,
				}},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			layer := mockLayer{&mock.Mock{}}
			if c.setup != nil {
				c.setup(&layer)
			}
			sp, err := SLSAProvenanceFromLayer(layer)
			if c.err == nil {
				require.Nil(t, err)
				require.NotNil(t, sp)
			} else {
				assert.True(t, c.err.Alike(err), "Expecting `%v` to be alike: `%v`", err, c.err)
				return
			}

			assert.Equal(t, c.signatures, sp.Signatures())
		})
	}
}

func encode(payload string) string {
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

func buffy(data string) io.ReadCloser {
	return io.NopCloser(bytes.NewBufferString(data))
}
