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

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/policy"
	"github.com/sigstore/cosign/pkg/types"
)

// PipelineRunBuildType is the type of the attestation we're interested in evaluating
const PipelineRunBuildType = "https://tekton.dev/attestations/chains/pipelinerun@v2"

func fetchInputData(ctx context.Context, attestations []oci.Signature) ([]string, error) {
	inputs := make([]string, 0, len(attestations))
	for _, att := range attestations {
		typ, err := att.MediaType()
		if err != nil {
			return nil, err
		}

		if typ != types.DssePayloadType {
			continue
		}
		payload, err := policy.AttestationToPayloadJSON(ctx, "slsaprovenance", att)
		if err != nil {
			return nil, err
		}

		var statement in_toto.Statement
		err = json.Unmarshal(payload, &statement)
		if err != nil {
			return nil, err
		}

		predicates, ok := statement.Predicate.(map[string]interface{})
		if !ok {
			return nil, errors.New("expecting map with string keys in in-toto Statement, did not find it")
		}

		if predicates["buildType"] != PipelineRunBuildType {
			continue
		}

		inputDir, err := os.MkdirTemp("", "ecp_input.*")
		if err != nil {
			return nil, err
		}

		inputJSONPath := path.Join(inputDir, "input.json")
		input, err := os.Create(inputJSONPath)
		if err != nil {
			return nil, err
		}
		defer input.Close()

		fmt.Fprint(input, `{"attestations":[`)
		j := json.NewEncoder(input)
		err = j.Encode(statement)
		if err != nil {
			return nil, err
		}
		fmt.Fprint(input, `]}`)

		inputs = append(inputs, inputJSONPath)
	}

	return inputs, nil
}
