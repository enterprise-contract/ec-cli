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
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/enterprise-contract/ec-cli/internal/attestation"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/mocks"
	"github.com/enterprise-contract/ec-cli/internal/output"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/sigstore"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

// pipelineRunBuildType is the type of attestation we're interested in evaluating
const pipelineRunBuildType = "https://tekton.dev/attestations/chains/pipelinerun@v2"

func TestNewApplicationSnapshotImage(t *testing.T) {
	ctx := context.Background()
	p, err := policy.NewOfflinePolicy(ctx, policy.Now)
	require.NoError(t, err)

	asi, err := NewApplicationSnapshotImage(ctx, "example.com/test:latest", p)
	require.NoError(t, err)

	assert.Len(t, asi.Validators, 1)
}

func TestApplicationSnapshotImage_ValidateImageAccess(t *testing.T) {
	type fields struct {
		reference    name.Reference
		checkOpts    cosign.CheckOpts
		attestations []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]
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
				Evaluators:   []evaluator.Evaluator{tt.fields.Evaluator},
			}
			if err := a.ValidateImageAccess(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("ValidateImageAccess() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type fakeAtt struct {
	statement in_toto.ProvenanceStatementSLSA02
}

func (f fakeAtt) Data() []byte {
	bytes, err := json.Marshal(f.statement)
	if err != nil {
		panic(err)
	}
	return bytes
}

func (f fakeAtt) Statement() in_toto.ProvenanceStatementSLSA02 {
	return f.statement
}

func (f fakeAtt) Signatures() []output.EntitySignature {
	return nil
}

func createSimpleAttestation(statement *in_toto.ProvenanceStatementSLSA02) attestation.Attestation[in_toto.ProvenanceStatementSLSA02] {
	if statement == nil {
		statement = &in_toto.ProvenanceStatementSLSA02{
			StatementHeader: in_toto.StatementHeader{
				Type:          in_toto.StatementInTotoV01,
				PredicateType: v02.PredicateSLSAProvenance,
			},
			Predicate: v02.ProvenancePredicate{
				BuildType: pipelineRunBuildType,
			},
		}
	}

	return fakeAtt{statement: *statement}
}

const simpleAttestationJSONText = `{
	"_type": "https://in-toto.io/Statement/v0.1",
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
}`

func TestWriteInputFile(t *testing.T) {
	cases := []struct {
		name     string
		snapshot ApplicationSnapshotImage
		want     string
	}{
		{
			name: "single attestations",
			snapshot: ApplicationSnapshotImage{
				reference:    name.MustParseReference("registry.io/repository/image:tag"),
				attestations: []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{createSimpleAttestation(nil)},
			},
			want: `{"attestations": [` + simpleAttestationJSONText + `], "image": {"ref": "registry.io/repository/image:tag"}}`,
		},
		{
			name: "multiple attestations",
			snapshot: ApplicationSnapshotImage{
				reference: name.MustParseReference("registry.io/repository/image:tag"),
				attestations: []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{
					createSimpleAttestation(nil),
					createSimpleAttestation(nil),
				},
			},
			want: `{"attestations": [` + simpleAttestationJSONText + "," + simpleAttestationJSONText + `], "image": {"ref": "registry.io/repository/image:tag"}}`,
		},
		{
			name: "image signatures",
			snapshot: ApplicationSnapshotImage{
				reference: name.MustParseReference("registry.io/repository/image:tag"),
				signatures: []output.EntitySignature{
					{
						KeyID:     "keyId1",
						Signature: "signature1",
						Chain:     []string{"certificate1", "certificate2"},
					},
					{
						KeyID:     "keyId2",
						Signature: "signature2",
					},
				},
				attestations: []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{
					createSimpleAttestation(nil),
				},
			},
			want: `{"attestations": [` + simpleAttestationJSONText + `], "image": {"ref": "registry.io/repository/image:tag", "signatures": [{"keyid": "keyId1", "sig": "signature1", "chain": ["certificate1", "certificate2"]}, {"keyid": "keyId2", "sig": "signature2"}]}}`,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			ctx := utils.WithFS(context.Background(), fs)
			input, err := tt.snapshot.WriteInputFile(ctx)

			assert.NoError(t, err)
			assert.NotEmpty(t, input)
			assert.Regexp(t, `/ecp_input.\d+/input.json`, input)
			fileExists, err := afero.Exists(fs, input)
			assert.NoError(t, err)
			assert.True(t, fileExists)

			bytes, err := afero.ReadFile(fs, input)
			assert.NoError(t, err)
			assert.JSONEq(t, tt.want, string(bytes))
		})
	}
}

func TestWriteInputFileMultipleAttestations(t *testing.T) {
	att := createSimpleAttestation(nil)
	a := ApplicationSnapshotImage{
		reference:    name.MustParseReference("registry.io/repository/image:tag"),
		attestations: []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{att},
	}

	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)
	input, err := a.WriteInputFile(ctx)

	assert.NoError(t, err)
	assert.NotEmpty(t, input)
	assert.Regexp(t, `/ecp_input.\d+/input.json`, input)
	fileExists, err := afero.Exists(fs, input)
	assert.NoError(t, err)
	assert.True(t, fileExists)

	bytes, err := afero.ReadFile(fs, input)
	assert.NoError(t, err)
	assert.JSONEq(t, `{"attestations": [`+simpleAttestationJSONText+`], "image": {"ref": "registry.io/repository/image:tag"}}`, string(bytes))
}

func TestSyntaxValidationWithoutAttestations(t *testing.T) {
	noAttestations := ApplicationSnapshotImage{}

	err := noAttestations.ValidateAttestationSyntax(context.TODO())
	assert.Error(t, err, "Expected error in validation")

	assert.True(t, strings.HasPrefix(err.Error(), "EV001: No attestation data"))
}

func TestSyntaxValidation(t *testing.T) {
	valid := createSimpleAttestation(&in_toto.ProvenanceStatementSLSA02{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: v02.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{
				{
					Name: "hello",
					Digest: common.DigestSet{
						"sha1": "abcdef0123456789",
					},
				},
			},
		},
		Predicate: v02.ProvenancePredicate{
			BuildType: pipelineRunBuildType,
			Builder: common.ProvenanceBuilder{
				ID: "scheme:uri",
			},
		},
	})

	invalid := createSimpleAttestation(&in_toto.ProvenanceStatementSLSA02{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: v02.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{
				{
					Name: "hello",
					Digest: common.DigestSet{
						"sha1": "abcdef0123456789",
					},
				},
			},
		},
		Predicate: v02.ProvenancePredicate{
			BuildType: pipelineRunBuildType,
			Builder: common.ProvenanceBuilder{
				ID: "invalid", // must be in URI syntax
			},
		},
	})

	cases := []struct {
		name         string
		attestations []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]
		err          *regexp.Regexp
	}{
		{
			name: "invalid",
			attestations: []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{
				invalid,
			},
			err: regexp.MustCompile(`EV003: Attestation syntax validation failed, .*, caused by:\nSchema ID: https://slsa.dev/provenance/v0.2\n - /predicate/builder/id: "invalid" invalid uri: uri missing scheme prefix`),
		},
		{
			name: "valid",
			attestations: []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{
				valid,
			},
		},
		{
			name: "empty",
			attestations: []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{
				createSimpleAttestation(&in_toto.ProvenanceStatementSLSA02{}),
			},
			err: regexp.MustCompile(`EV002: Unable to decode attestation data from attestation image, .*, caused by: unexpected end of JSON input`),
		},
		{
			name: "valid and invalid",
			attestations: []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{
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

type MockClient struct {
	mock.Mock
}

func (c *MockClient) VerifyImageSignatures(ctx context.Context, name name.Reference, opts *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	args := c.Called(ctx, name, opts)

	return args.Get(0).([]oci.Signature), args.Get(1).(bool), args.Error(2)
}

func (c *MockClient) VerifyImageAttestations(ctx context.Context, name name.Reference, opts *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	args := c.Called(ctx, name, opts)

	return args.Get(0).([]oci.Signature), args.Get(1).(bool), args.Error(2)
}

func (c *MockClient) Head(name name.Reference, options ...remote.Option) (*v1.Descriptor, error) {
	args := c.Called(name, options)

	return args.Get(0).(*v1.Descriptor), args.Error(1)
}

func TestValidateAttestationSignatureClaims(t *testing.T) {
	ref := name.MustParseReference("registry.io/repository/image:tag")
	a := ApplicationSnapshotImage{
		reference: ref,
	}

	c := MockClient{}

	ctx := WithClient(context.Background(), &c)
	ctx = sigstore.WithClient(ctx, &c)

	c.On("VerifyImageAttestations", ctx, ref, mock.Anything).Return([]oci.Signature{}, false, nil)

	err := a.ValidateAttestationSignature(ctx)
	require.NoError(t, err)

	call := c.Calls[0]

	checkOpts := call.Arguments.Get(2).(*cosign.CheckOpts)
	assert.NotNil(t, checkOpts)

	claimVerifier := checkOpts.ClaimVerifier
	assert.NotNil(t, claimVerifier)

	cases := []struct {
		name      string
		statement in_toto.Statement
		digest    v1.Hash
		err       error
	}{
		{
			name: "happy day",
			statement: in_toto.Statement{
				StatementHeader: in_toto.StatementHeader{
					Subject: []in_toto.Subject{
						{
							Digest: map[string]string{
								"sha256": "dabbad00",
							},
						},
					},
				},
			},
			digest: v1.Hash{Algorithm: "sha256", Hex: "dabbad00"},
		},
		{
			name: "happy day - multiple digests",
			statement: in_toto.Statement{
				StatementHeader: in_toto.StatementHeader{
					Subject: []in_toto.Subject{
						{
							Digest: map[string]string{
								"sha512": "dead10cc",
								"sha256": "dabbad00",
							},
						},
					},
				},
			},
			digest: v1.Hash{Algorithm: "sha256", Hex: "dabbad00"},
		},
		{
			name: "no digests",
			statement: in_toto.Statement{
				StatementHeader: in_toto.StatementHeader{
					Subject: []in_toto.Subject{},
				},
			},
			digest: v1.Hash{Algorithm: "sha256", Hex: "dabbad00"},
			err:    errors.New("no matching subject digest found"),
		},
		{
			name: "mismatched digests",
			statement: in_toto.Statement{
				StatementHeader: in_toto.StatementHeader{
					Subject: []in_toto.Subject{
						{
							Digest: map[string]string{
								"sha256": "dead10cc",
							},
						},
					},
				},
			},
			digest: v1.Hash{Algorithm: "sha256", Hex: "dabbad00"},
			err:    errors.New("no matching subject digest found"),
		},
		{
			name:      "empty statement",
			statement: in_toto.Statement{},
			digest:    v1.Hash{Algorithm: "sha256", Hex: "dabbad00"},
			err:       errors.New("no matching subject digest found"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			statementJSON, err := json.Marshal(c.statement)
			require.NoError(t, err)

			statement := base64.StdEncoding.EncodeToString(statementJSON)

			dsse := dsse.Envelope{
				Payload: statement,
			}

			payload, err := json.Marshal(dsse)
			require.NoError(t, err)

			signature, err := static.NewSignature(payload, "signature")
			require.NoError(t, err)

			err = claimVerifier(signature, c.digest, nil)
			assert.Equal(t, c.err, err)
		})
	}
}

func TestAddSignatures(t *testing.T) {
	a := ApplicationSnapshotImage{}
	assert.Empty(t, a.Signatures())
	a.AddSignatures(output.EntitySignature{})
	assert.Len(t, a.Signatures(), 1)
	a.AddSignatures(output.EntitySignature{})
	assert.Len(t, a.Signatures(), 2)
}
