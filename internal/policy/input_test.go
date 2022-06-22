/*
Copyright © 2022 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package policy

import (
	"context"
	_ "embed"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/stretchr/testify/assert"
)

func Test_fetchInputDataEmpty(t *testing.T) {
	inputDirs, err := fetchInputData(context.TODO(), []oci.Signature{})
	assert.NoError(t, err)
	assert.Empty(t, inputDirs, "not expecting to return any inputs with no attestations")
}

//go:embed test_attestation_payload_1.json
var testAttestationPayload1 []byte

//go:embed test_attestation_payload_2.json
var testAttestationPayload2 []byte

func testAttestations() ([]oci.Signature, error) {
	att1, err := static.NewAttestation(testAttestationPayload1, static.WithLayerMediaType(types.DssePayloadType))
	if err != nil {
		return nil, err
	}

	att2, err := static.NewAttestation(testAttestationPayload2, static.WithLayerMediaType(types.DssePayloadType))
	if err != nil {
		return nil, err
	}

	return []oci.Signature{
		att1,
		att2,
	}, nil
}

//go:embed test_pipelinerun_attestation_payload.json
var testPipelinerunAttestationPayload []byte

func Test_fetchInputData(t *testing.T) {
	attestations, err := testAttestations()
	assert.NoError(t, err)

	inputs, err := fetchInputData(context.TODO(), attestations)
	defer func() {
		for _, d := range inputs {
			os.RemoveAll(d)
		}
	}()

	assert.NoError(t, err)
	assert.Len(t, inputs, 1, "only one of the attestations is a pipelinerun attestation")

	assert.FileExists(t, inputs[0], "expecting input.json at %s", inputs[0])

	pipelineRunAttestation, err := ioutil.ReadFile(inputs[0])
	assert.NoError(t, err)

	var expected, actual interface{}
	assert.NoError(t, json.Unmarshal(testPipelinerunAttestationPayload, &expected))
	assert.NoError(t, json.Unmarshal(pipelineRunAttestation, &actual))
	assert.Equal(t, map[string]interface{}{
		"attestations": []interface{}{expected},
	}, actual)
}
