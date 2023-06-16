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

package slsa

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/enterprise-contract/ec-cli/internal/validator"
)

const ProvenanceV0_2ValidatorName = "in-toto-slsa-provenance-v0.2"

type ProvenanceV0_2Validator struct {
	opts validator.Options
}

func (ProvenanceV0_2Validator) Validate(ctx context.Context, image name.Reference) *validator.ImageResult {
	// TODO: Move the logic from ValidateImage regarding SLSA Provenance v0.2 attestations here.
	// A validator can use an evaluator. Here, we'll use the conftest_evaluator.
	return nil
}

func init() {
	v := func(opts validator.Options) validator.ImageValidator {
		return ProvenanceV0_2Validator{opts: opts}
	}
	if err := validator.RegisterImageValidator(ProvenanceV0_2ValidatorName, v); err != nil {
		panic(err)
	}
}
