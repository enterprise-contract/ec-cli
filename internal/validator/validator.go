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

package validator

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	confOutput "github.com/open-policy-agent/conftest/output"

	"github.com/enterprise-contract/ec-cli/internal/output"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
)

type ImageValidator interface {
	Validate(context.Context, name.Reference) *ImageResult
}

type Options struct {
	Policy     policy.Policy
	PolicyURLs []source.PolicyUrl
	// TODO: Convert RuleData to just another kind of PolicyURL?
	// TODO: Add support for ruleData
	// RuleData map[string]string
}

type ImageResult struct {
	// TODO: Remove dependency on conftest/output.Result
	Violations []confOutput.Result
	Warnings   []confOutput.Result
	Successes  []confOutput.Result
	Signatures []output.EntitySignature
	// TODO: Add support for Attestations
}

type imageInitializer func(Options) ImageValidator

var imageValidators = map[string]imageInitializer{}

func RegisterImageValidator(name string, v imageInitializer) error {
	if _, ok := imageValidators[name]; ok {
		return fmt.Errorf("validator named %q has already been registered", name)
	}
	imageValidators[name] = v
	return nil
}

func NewImageValidator(name string, opts Options) (ImageValidator, error) {
	v, ok := imageValidators[name]
	if !ok {
		return nil, fmt.Errorf("validator named %q not found", name)
	}
	return v(opts), nil
}
