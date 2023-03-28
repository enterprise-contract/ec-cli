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
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/enterprise-contract/ec-cli/internal/attestation"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/mocks"
	"github.com/enterprise-contract/ec-cli/internal/output"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

// pipelineRunBuildType is the type of attestation we're interested in evaluating
const pipelineRunBuildType = "https://tekton.dev/attestations/chains/pipelinerun@v2"

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
				attestations: []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{createSimpleAttestation(nil)},
			},
			want: `{"attestations": [` + simpleAttestationJSONText + `]}`,
		},
		{
			name: "multiple attestations",
			snapshot: ApplicationSnapshotImage{
				attestations: []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{
					createSimpleAttestation(nil),
					createSimpleAttestation(nil),
				},
			},
			want: `{"attestations": [` + simpleAttestationJSONText + "," + simpleAttestationJSONText + `]}`,
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
	assert.JSONEq(t, `{"attestations": [`+simpleAttestationJSONText+`]}`, string(bytes))
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

func TestFilterMatchingAttestations(t *testing.T) {
	knownDigest := "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
	unknownDigest := "284e3029cce3ae5ee0b05866100e300046359f53ae4c77fe6b34c05aa7a72cee"

	singleSubject := createSimpleAttestation(&in_toto.ProvenanceStatementSLSA02{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: v02.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{
				{Digest: common.DigestSet{"sha256": knownDigest}},
			},
		},
	})

	multipleSubjects := createSimpleAttestation(&in_toto.ProvenanceStatementSLSA02{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: v02.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{
				{Digest: common.DigestSet{"sha256": unknownDigest}},
				{Digest: common.DigestSet{"sha256": knownDigest}},
			},
		},
	})

	unknownSubject := createSimpleAttestation(&in_toto.ProvenanceStatementSLSA02{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: v02.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{
				{Digest: common.DigestSet{"sha256": unknownDigest}},
			},
		},
	})

	// nil is used here to easily simulate an invalid attestation
	var invalidAttestation attestation.Attestation[in_toto.ProvenanceStatementSLSA02] = nil

	reference, err := name.ParseReference("registry/image:tag@sha256:" + knownDigest)
	assert.NoError(t, err)

	a := ApplicationSnapshotImage{
		attestations: []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{singleSubject, unknownSubject, invalidAttestation, multipleSubjects},
		reference:    reference,
	}
	a.FilterMatchingAttestations(context.Background())
	expected := []attestation.Attestation[in_toto.ProvenanceStatementSLSA02]{singleSubject, multipleSubjects}
	assert.Equal(t, expected, a.attestations)
}
