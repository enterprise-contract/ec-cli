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

package evaluator

import (
	"context"
	"testing"

	"github.com/open-policy-agent/conftest/output"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/policy/source"
)

type fakeClient struct {
	results []output.CheckResult
}

func (c *fakeClient) Run(ctx context.Context, fileList []string) ([]output.CheckResult, error) {
	return c.results, nil
}

func TestConftestEvaluatorEvaluate(t *testing.T) {
	results := []output.CheckResult{
		{
			Failures: []output.Result{
				{
					Message:  "missing effective date",
					Metadata: map[string]interface{}{},
				},
				{
					Message: "already effective",
					Metadata: map[string]interface{}{
						"effective_on": "2021-01-01T00:00:00Z",
					},
				},
				{
					Message: "invalid effective date",
					Metadata: map[string]interface{}{
						"effective_on": "hangout-not-a-date",
					},
				},
				{
					Message: "unexpected effective date type",
					Metadata: map[string]interface{}{
						"effective_on": true,
					},
				},
				{
					Message: "not yet effective",
					Metadata: map[string]interface{}{
						"effective_on": "3021-01-01T00:00:00Z",
					},
				},
			},
			Warnings: []output.Result{
				{
					Message: "existing warning",
					Metadata: map[string]interface{}{
						"effective_on": "2021-01-01T00:00:00Z",
					},
				},
			},
		},
	}

	expectedResults := []output.CheckResult{
		{
			Failures: []output.Result{
				{
					Message:  "missing effective date",
					Metadata: map[string]interface{}{},
				},
				{
					Message: "already effective",
					Metadata: map[string]interface{}{
						"effective_on": "2021-01-01T00:00:00Z",
					},
				},
				{
					Message: "invalid effective date",
					Metadata: map[string]interface{}{
						"effective_on": "hangout-not-a-date",
					},
				},
				{
					Message: "unexpected effective date type",
					Metadata: map[string]interface{}{
						"effective_on": true,
					},
				},
			},
			Warnings: []output.Result{
				{
					Message: "existing warning",
					Metadata: map[string]interface{}{
						"effective_on": "2021-01-01T00:00:00Z",
					},
				},
				{
					Message: "not yet effective",
					Metadata: map[string]interface{}{
						"effective_on": "3021-01-01T00:00:00Z",
					},
				},
			},
		},
	}

	ctx := withClient(context.Background(), &fakeClient{results: results})
	evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{}, "release.main", nil)
	assert.NoError(t, err)
	actualResults, err := evaluator.Evaluate(ctx, []string{})
	assert.NoError(t, err)
	assert.Equal(t, expectedResults, actualResults)
}
