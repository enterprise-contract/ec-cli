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
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
	cosignTypes "github.com/sigstore/cosign/pkg/types"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/hacbs-contract/ec-cli/internal/evaluator"
	"github.com/hacbs-contract/ec-cli/internal/mocks"
)

// pipelineRunBuildType is the type of attestation we're interested in evaluating
const pipelineRunBuildType = "https://tekton.dev/attestations/chains/pipelinerun@v2"

func TestApplicationSnapshotImage_ValidateImageAccess(t *testing.T) {
	type fields struct {
		reference    name.Reference
		checkOpts    cosign.CheckOpts
		attestations []oci.Signature
		Evaluator    evaluator.Evaluator
	}
	type args struct {
		ctx context.Context
	}
	ref, _ := name.ParseReference("registry/image:tag")
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Returns no error when able to access image ref",
			fields: fields{
				reference:    ref,
				checkOpts:    cosign.CheckOpts{},
				attestations: nil,
				Evaluator:    nil,
			},
			args:    args{ctx: context.Background()},
			wantErr: false,
		},
		{
			name: "Returns error when unable to access image ref",
			fields: fields{
				reference:    ref,
				checkOpts:    cosign.CheckOpts{},
				attestations: nil,
				Evaluator:    nil,
			},
			args:    args{ctx: context.Background()},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr {
				imageRefTransport = remote.WithTransport(&mocks.HttpTransportMockFailure{})
			} else {
				imageRefTransport = remote.WithTransport(&mocks.HttpTransportMockSuccess{})
			}
			a := &ApplicationSnapshotImage{
				reference:    tt.fields.reference,
				checkOpts:    tt.fields.checkOpts,
				attestations: tt.fields.attestations,
				Evaluator:    tt.fields.Evaluator,
			}
			if err := a.ValidateImageAccess(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("ValidateImageAccess() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func createSimpleAttestation(statement *in_toto.Statement) oci.Signature {
	if statement == nil {
		statement = &in_toto.Statement{
			StatementHeader: in_toto.StatementHeader{
				PredicateType: v02.PredicateSLSAProvenance,
			},
			Predicate: v02.ProvenancePredicate{
				BuildType: pipelineRunBuildType,
			},
		}
	}

	statementJson, err := json.Marshal(statement)
	if err != nil {
		panic(err)
	}

	payload := base64.StdEncoding.EncodeToString(statementJson)

	signature, err := static.NewSignature([]byte(`{"payload":"`+payload+`"}`), "signature", static.WithLayerMediaType(types.MediaType((cosignTypes.DssePayloadType))))
	if err != nil {
		panic(err)
	}

	return signature
}

func TestWriteInputFiles(t *testing.T) {
	att := createSimpleAttestation(nil)
	a := ApplicationSnapshotImage{
		attestations: []oci.Signature{att},
	}

	fs := afero.NewMemMapFs()
	inputs, err := a.WriteInputFiles(context.TODO(), fs)

	assert.NoError(t, err)
	assert.Len(t, inputs, 1)
	assert.Regexp(t, `/ecp_input.\d+/input.json`, inputs[0])
	fileExists, err := afero.Exists(fs, inputs[0])
	assert.NoError(t, err)
	assert.True(t, fileExists)

	bytes, err := afero.ReadFile(fs, inputs[0])
	assert.NoError(t, err)
	assert.JSONEq(t, `{
		"attestations": [
		  {
			"_type": "",
			"predicateType": "https://slsa.dev/provenance/v0.2",
			"subject": null,
			"predicate": {
			  "buildType": "https://tekton.dev/attestations/chains/pipelinerun@v2",
			  "builder": {
				"id": ""
			  },
			  "invocation": {
				"configSource": {}
			  }
			}
		  }
		]
	  }
	  `, string(bytes))
}

func TestSyntaxValidationWithoutAttestations(t *testing.T) {
	noAttestations := ApplicationSnapshotImage{}

	err := noAttestations.ValidateAttestationSyntax(context.TODO())
	assert.Error(t, err, "Expected error in validation")

	assert.True(t, strings.HasPrefix(err.Error(), "EV001: No attestation data"))
}

func TestSyntaxValidation(t *testing.T) {
	valid := createSimpleAttestation(&in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: v02.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{
				{
					Name: "hello",
					Digest: v02.DigestSet{
						"sha1": "abcdef0123456789",
					},
				},
			},
		},
		Predicate: v02.ProvenancePredicate{
			BuildType: pipelineRunBuildType,
			Builder: v02.ProvenanceBuilder{
				ID: "scheme:uri",
			},
		},
	})

	invalid := createSimpleAttestation(&in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: v02.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{
				{
					Name: "hello",
					Digest: v02.DigestSet{
						"sha1": "abcdef0123456789",
					},
				},
			},
		},
		Predicate: v02.ProvenancePredicate{
			BuildType: pipelineRunBuildType,
			Builder: v02.ProvenanceBuilder{
				ID: "invalid", // must be in URI syntax
			},
		},
	})

	cases := []struct {
		name         string
		attestations []oci.Signature
		err          *regexp.Regexp
	}{
		{
			name: "invalid",
			attestations: []oci.Signature{
				invalid,
			},
			err: regexp.MustCompile(`EV003: Attestation syntax validation failed, .*, caused by:\nSchema ID: https://slsa.dev/provenance/v0.2\n - /predicate/builder/id: "invalid" invalid uri: uri missing scheme prefix`),
		},
		{
			name: "valid",
			attestations: []oci.Signature{
				valid,
			},
		},
		{
			name: "empty",
			attestations: []oci.Signature{
				createSimpleAttestation(&in_toto.Statement{}),
			},
			err: regexp.MustCompile(`EV002: Unable to decode attestation data from attestation image, .*, caused by: unexpected end of JSON input`),
		},
		{
			name: "valid and invalid",
			attestations: []oci.Signature{
				valid,
				invalid,
			},
			err: regexp.MustCompile(`EV003`),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := ApplicationSnapshotImage{
				attestations: c.attestations,
			}

			err := a.ValidateAttestationSyntax(context.TODO())
			if c.err == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Regexp(t, err, err.Error())
			}
		})
	}
}

type mockSignature struct {
	*mock.Mock
}

func (m mockSignature) Annotations() (map[string]string, error) {
	args := m.Called()
	return args.Get(0).(map[string]string), args.Error(1)
}

func (m mockSignature) Payload() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (m mockSignature) Base64Signature() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m mockSignature) Cert() (*x509.Certificate, error) {
	args := m.Called()
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

func (m mockSignature) Chain() ([]*x509.Certificate, error) {
	args := m.Called()
	return args.Get(0).([]*x509.Certificate), args.Error(1)
}

func (m mockSignature) Bundle() (*bundle.RekorBundle, error) {
	args := m.Called()
	return args.Get(0).(*bundle.RekorBundle), args.Error(1)
}

func (m mockSignature) Digest() (v1.Hash, error) {
	args := m.Called()
	return args.Get(0).(v1.Hash), args.Error(1)
}

func (m mockSignature) DiffID() (v1.Hash, error) {
	args := m.Called()
	return args.Get(0).(v1.Hash), args.Error(1)
}

func (m mockSignature) Compressed() (io.ReadCloser, error) {
	args := m.Called()
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m mockSignature) Uncompressed() (io.ReadCloser, error) {
	args := m.Called()
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m mockSignature) Size() (int64, error) {
	args := m.Called()
	return int64(args.Int(0)), args.Error(1)
}

func (m mockSignature) MediaType() (types.MediaType, error) {
	args := m.Called()
	return args.Get(0).(types.MediaType), args.Error(1)
}

func TestStatementFrom(t *testing.T) {
	cases := []struct {
		name      string
		signature *mockSignature
		setup     func(*mockSignature)
		json      string
		statement *in_toto.Statement
		err       error
	}{
		{
			name: "nil signature",
			err:  errors.New("no signature provided"),
		},
		{
			name:      "media type error",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				m.On("MediaType").Return(types.MediaType(""), errors.New("expected"))
			},
			err: errors.New("expected"),
		},
		{
			name:      "no media type",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				m.On("MediaType").Return(types.MediaType(""), nil)
			},
		},
		{
			name:      "unsupported media type",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				m.On("MediaType").Return(types.MediaType("xxx"), nil)
			},
		},
		{
			name:      "no payload JSON",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				m.On("MediaType").Return(types.MediaType(cosignTypes.DssePayloadType), nil)
				m.On("Payload").Return([]byte{}, nil)
			},
			err: errors.New("unmarshaling payload data"),
		},
		{
			name:      "empty payload JSON",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				m.On("MediaType").Return(types.MediaType(cosignTypes.DssePayloadType), nil)
				m.On("Payload").Return([]byte(`{"payload":"`+base64.StdEncoding.EncodeToString([]byte("{}"))+`"}`), nil)
			},
		},
		{
			name:      "valid",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				m.On("MediaType").Return(types.MediaType(cosignTypes.DssePayloadType), nil)
				m.On("Payload").Return([]byte(`{"payload":"`+base64.StdEncoding.EncodeToString([]byte(`{"predicateType":"https://slsa.dev/provenance/v0.2","predicate":{"buildType":"`+pipelineRunBuildType+`"}}`))+`"}`), nil)
			},
			json: `{"_type":"","predicateType":"https://slsa.dev/provenance/v0.2","subject":null,"predicate":{"builder":{"id":""},"buildType":"https://tekton.dev/attestations/chains/pipelinerun@v2","invocation": {"configSource": {}}}}`,
			statement: &in_toto.Statement{
				StatementHeader: in_toto.StatementHeader{
					PredicateType: "https://slsa.dev/provenance/v0.2",
				},
				Predicate: map[string]any{
					"buildType": pipelineRunBuildType,
					"builder":   map[string]any{"id": ""},
					"invocation": map[string]any{
						"configSource": map[string]any{},
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.setup != nil {
				c.setup(c.signature)
			}
			var sig oci.Signature
			if c.signature == nil {
				sig = nil
			} else {
				sig = c.signature
			}
			bytes, statement, err := statementFrom(context.TODO(), sig)

			if c.json == "" {
				assert.Nil(t, bytes)
			} else {
				assert.JSONEq(t, c.json, string(bytes))
			}
			assert.Equal(t, c.statement, statement)
			assert.Equal(t, c.err, err)
		})
	}
}

func TestSignaturesFrom(t *testing.T) {
	cases := []struct {
		name       string
		signature  *mockSignature
		setup      func(*mockSignature)
		signatures []cosign.Signatures
		err        error
	}{
		{
			name:      "missing signatures",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				m.On("Payload").Return([]byte("{}"), nil)
			},
		},
		{
			name:      "invalid signature JSON",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				m.On("Payload").Return([]byte(`{{{{"signatures": []}`), nil)
			},
			err: errors.New("invalid character '{' looking for beginning of object key string"),
		},
		{
			name:      "valid",
			signature: &mockSignature{&mock.Mock{}},
			setup: func(m *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				sig2 := `{"keyid": "key-id-2", "sig": "sig-2"}`
				payload := fmt.Sprintf(`{"signatures": [%s, %s]}`, sig1, sig2)
				m.On("Payload").Return([]byte(payload), nil)
			},
			signatures: []cosign.Signatures{
				{KeyID: "key-id-1", Sig: "sig-1"},
				{KeyID: "key-id-2", Sig: "sig-2"},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.setup != nil {
				c.setup(c.signature)
			}
			signatures, err := signaturesFrom(context.TODO(), c.signature)
			if c.err != nil {
				assert.Error(t, c.err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, c.signatures, signatures)
		})
	}
}

func TestFilterMatchingAttestations(t *testing.T) {
	knownDigest := "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
	unknownDigest := "284e3029cce3ae5ee0b05866100e300046359f53ae4c77fe6b34c05aa7a72cee"

	singleSubject := createSimpleAttestation(&in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: v02.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{
				{Digest: v02.DigestSet{"sha256": knownDigest}},
			},
		},
	})

	multipleSubjects := createSimpleAttestation(&in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: v02.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{
				{Digest: v02.DigestSet{"sha256": unknownDigest}},
				{Digest: v02.DigestSet{"sha256": knownDigest}},
			},
		},
	})

	unknownSubject := createSimpleAttestation(&in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: v02.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{
				{Digest: v02.DigestSet{"sha256": unknownDigest}},
			},
		},
	})

	// nil is used here to easily simulate an invalid attestation
	var invalidAttestation oci.Signature = nil

	reference, err := name.ParseReference("registry/image:tag@sha256:" + knownDigest)
	assert.NoError(t, err)

	a := ApplicationSnapshotImage{
		attestations: []oci.Signature{singleSubject, unknownSubject, invalidAttestation, multipleSubjects},
		reference:    reference,
	}
	a.FilterMatchingAttestations(context.Background())
	expected := []oci.Signature{singleSubject, multipleSubjects}
	assert.Equal(t, expected, a.attestations)
}
