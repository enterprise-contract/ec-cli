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

package pipeline

import (
	"context"

	"github.com/hacbs-contract/ec-cli/internal/policy"
)

//ValidatePipeline calls NewPipelineEvaluator to obtain an Evaluator. It then executes the associated TestRunner
//which tests the associated pipeline file(s) against the associated policies, and displays the output.
func ValidatePipeline(ctx context.Context, fpath string, policyRepo PolicyRepo, namespace string) (*policy.Output, error) {
	e, err := NewPipelineEvaluator(ctx, fpath, policyRepo, namespace)
	if err != nil {
		return nil, err
	}
	results, err := e.TestRunner.Run(ctx, []string{fpath})
	if err != nil {
		return nil, err
	}

	return &policy.Output{PolicyCheck: results}, nil
}
