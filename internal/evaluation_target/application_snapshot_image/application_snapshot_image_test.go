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
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
	cosignTypes "github.com/sigstore/cosign/pkg/types"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/evaluator"
	"github.com/hacbs-contract/ec-cli/internal/mocks"
)

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

func createSimpleAttestation() (oci.Signature, error) {
	statement := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			PredicateType: v02.PredicateSLSAProvenance,
		},
		Predicate: v02.ProvenancePredicate{
			BuildType: PipelineRunBuildType,
		},
	}
	statementJson, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}

	payload := base64.StdEncoding.EncodeToString(statementJson)

	return static.NewSignature([]byte(`{"payload":"`+payload+`"}`), "signature", static.WithLayerMediaType(types.MediaType((cosignTypes.DssePayloadType))))
}

func TestWriteInputFiles(t *testing.T) {
	att, err := createSimpleAttestation()
	assert.NoError(t, err)
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
