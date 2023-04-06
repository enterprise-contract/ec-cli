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

package evaluator

import (
	"context"
	"testing"
	"time"

	"github.com/MakeNowJust/heredoc"
	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/open-policy-agent/conftest/output"
	"github.com/open-policy-agent/opa/ast"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/enterprise-contract/ec-cli/internal/downloader"
	"github.com/enterprise-contract/ec-cli/internal/opa/rule"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

type mockTestRunner struct {
	mock.Mock
}

func (m *mockTestRunner) Run(ctx context.Context, inputs []string) ([]output.CheckResult, error) {
	args := m.Called(ctx, inputs)

	return args.Get(0).([]output.CheckResult), args.Error(1)
}

func withTestRunner(ctx context.Context, clnt testRunner) context.Context {
	return context.WithValue(ctx, runnerKey, clnt)
}

type testPolicySource struct{}

func (t testPolicySource) GetPolicy(ctx context.Context, dest string, showMsg bool) (string, error) {
	return "/policy", nil
}

func (t testPolicySource) PolicyUrl() string {
	return "test-url"
}

func (t testPolicySource) Subdir() string {
	return "policy"
}

type mockDownloader struct {
	mock.Mock
}

func (m *mockDownloader) Download(ctx context.Context, dest string, urls []string) error {
	args := m.Called(ctx, dest, urls)

	return args.Error(0)
}

func TestConftestEvaluatorEvaluate(t *testing.T) {
	results := []output.CheckResult{
		{
			Failures: []output.Result{
				{
					Message:  "missing effective date",
					Metadata: map[string]any{},
				},
				{
					Message: "already effective",
					Metadata: map[string]any{
						"effective_on": "2021-01-01T00:00:00Z",
					},
				},
				{
					Message: "invalid effective date",
					Metadata: map[string]any{
						"effective_on": "hangout-not-a-date",
					},
				},
				{
					Message: "unexpected effective date type",
					Metadata: map[string]any{
						"effective_on": true,
					},
				},
				{
					Message: "not yet effective",
					Metadata: map[string]any{
						"effective_on": "3021-01-01T00:00:00Z",
					},
				},
			},
			Warnings: []output.Result{
				{
					Message: "existing warning",
					Metadata: map[string]any{
						"effective_on": "2021-01-01T00:00:00Z",
					},
				},
			},
		},
	}

	expectedResults := CheckResults{
		{
			CheckResult: output.CheckResult{
				Failures: []output.Result{
					{
						Message:  "missing effective date",
						Metadata: map[string]any{},
					},
					{
						Message: "already effective",
						Metadata: map[string]any{
							"effective_on": "2021-01-01T00:00:00Z",
						},
					},
					{
						Message: "invalid effective date",
						Metadata: map[string]any{
							"effective_on": "hangout-not-a-date",
						},
					},
					{
						Message: "unexpected effective date type",
						Metadata: map[string]any{
							"effective_on": true,
						},
					},
				},
				Warnings: []output.Result{
					{
						Message: "existing warning",
						Metadata: map[string]any{
							"effective_on": "2021-01-01T00:00:00Z",
						},
					},
					{
						Message: "not yet effective",
						Metadata: map[string]any{
							"effective_on": "3021-01-01T00:00:00Z",
						},
					},
				},
				Skipped:    []output.Result{},
				Exceptions: []output.Result{},
			},
		},
	}

	r := mockTestRunner{}

	dl := mockDownloader{}

	inputs := []string{"inputs"}

	ctx := setupTestContext(&r, &dl)

	r.On("Run", ctx, inputs).Return(results, nil)

	pol, err := policy.NewOfflinePolicy(ctx, policy.Now)
	assert.NoError(t, err)

	evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{
		testPolicySource{},
	}, pol)

	assert.NoError(t, err)
	actualResults, err := evaluator.Evaluate(ctx, inputs)
	assert.NoError(t, err)
	assert.Equal(t, expectedResults, actualResults)
}

func setupTestContext(r *mockTestRunner, dl *mockDownloader) context.Context {
	ctx := withTestRunner(context.Background(), r)
	ctx = downloader.WithDownloadImpl(ctx, dl)
	fs := afero.NewMemMapFs()
	ctx = utils.WithFS(ctx, fs)

	if err := afero.WriteFile(fs, "/policy/example.rego", []byte(heredoc.Doc(`# Simplest always-failing policy
	package main

	# METADATA
	# title: Reject rule
	# description: This rule will always fail
	deny[result] {
		result := "Fails always"
	}`)), 0644); err != nil {
		panic(err)
	}

	return ctx
}

func TestConftestEvaluatorEvaluateNoSuccessWarningsOrFailures(t *testing.T) {
	results := []output.CheckResult{
		{
			Failures:  []output.Result(nil),
			Warnings:  []output.Result(nil),
			Successes: 0,
		},
	}

	expectedResults := CheckResults(nil)

	r := mockTestRunner{}

	dl := mockDownloader{}

	inputs := []string{"inputs"}

	ctx := setupTestContext(&r, &dl)

	r.On("Run", ctx, inputs).Return(results, nil)

	p, err := policy.NewOfflinePolicy(ctx, policy.Now)
	assert.NoError(t, err)

	evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{
		testPolicySource{},
	}, p)

	assert.NoError(t, err)
	actualResults, err := evaluator.Evaluate(ctx, inputs)
	assert.ErrorContains(t, err, "no successes, warnings, or failures, check input")
	assert.Equal(t, expectedResults, actualResults)
}

func TestConftestEvaluatorIncludeExclude(t *testing.T) {
	tests := []struct {
		name    string
		results []output.CheckResult
		config  *ecc.EnterpriseContractPolicyConfiguration
		want    CheckResults
	}{
		{
			name: "exclude by package name",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast"}},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{"code": "lunch.spam"}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{"code": "lunch.ham"}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "exclude by package name with wild card",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast.*"}},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{"code": "lunch.spam"}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{"code": "lunch.ham"}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "exclude by package and rule name",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Exclude: []string{"breakfast.spam", "lunch.ham"},
			},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{"code": "lunch.spam"}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.ham"}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "exclude by package name with term",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast:eggs"}},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
							{Metadata: map[string]any{"code": "breakfast.sausage"}},
							{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
							{Metadata: map[string]any{"code": "breakfast.hash"}},
							{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "exclude by package name with wildcard and term",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast.*:eggs"}},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
							{Metadata: map[string]any{"code": "breakfast.sausage"}},
							{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
							{Metadata: map[string]any{"code": "breakfast.hash"}},
							{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "exclude by package and rule name with term",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Exclude: []string{"breakfast.spam:eggs", "breakfast.ham:eggs"},
			},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
							{Metadata: map[string]any{"code": "breakfast.sausage"}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
							{Metadata: map[string]any{"code": "breakfast.hash"}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "exclude by collection",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []any{"bar"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.spam",
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []any{"bar"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.ham",
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"@foo"}},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{
								"code": "lunch.spam", "collections": []string{"bar"},
							}},
							{Metadata: map[string]any{
								"code": "dinner.spam",
							}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{
								"code": "lunch.ham", "collections": []string{"bar"},
							}},
							{Metadata: map[string]any{
								"code": "dinner.ham",
							}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "include by package",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast"}},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.spam"}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.ham"}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "include by package with wildcard",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast.*"}},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.spam"}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.ham"}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "include by package and rule name with exclude wildcard",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "breakfast.eggs"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"*", "breakfast.spam", "breakfast.ham"},
				Exclude: []string{"breakfast.*"},
			},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.spam"}},
							{Metadata: map[string]any{"code": "lunch.spam"}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.ham"}},
							{Metadata: map[string]any{"code": "lunch.ham"}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "include by package and rule name",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"breakfast.spam", "lunch.ham"},
			},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.spam"}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{"code": "lunch.ham"}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "include by package with term",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast:eggs"}},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "include by package with wildcard and term",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast.*:eggs"}},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "include by package and rule name with term",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"breakfast.spam:eggs", "breakfast.ham:eggs"},
			},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "include by old-style collection",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []any{"bar"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.spam",
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []any{"bar"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.ham",
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Collections: []string{"foo"}},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{
								"code": "breakfast.spam", "collections": []string{"foo"},
							}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{
								"code": "breakfast.ham", "collections": []string{"foo"},
							}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "include by collection",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							// Different collection
							"code": "lunch.spam", "collections": []any{"bar"},
						}},
						{Metadata: map[string]any{
							// No collections at all
							"code": "dinner.spam",
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"foo"}, // intentional to test normalization to []string
						}},
						{Metadata: map[string]any{
							// Different collection
							"code": "lunch.ham", "collections": []any{"bar"},
						}},
						{Metadata: map[string]any{
							// No collections at all
							"code": "dinner.ham",
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"@foo"}},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{
								"code": "breakfast.spam", "collections": []string{"foo"},
							}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{
								"code": "breakfast.ham", "collections": []string{"foo"},
							}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "include by collection and package",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"other"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.spam",
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"other"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.ham",
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"breakfast", "@foo"},
			},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{
								"code": "breakfast.spam", "collections": []string{"other"},
							}},
							{Metadata: map[string]any{
								"code": "lunch.spam", "collections": []string{"foo"},
							}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{
								"code": "breakfast.ham", "collections": []string{"other"},
							}},
							{Metadata: map[string]any{
								"code": "lunch.ham", "collections": []string{"foo"},
							}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "include by collection and exclude by package",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []any{"foo"},
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []any{"foo"},
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"@foo"},
				Exclude: []string{"lunch"},
			},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{
								"code": "breakfast.spam", "collections": []string{"foo"},
							}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{
								"code": "breakfast.ham", "collections": []string{"foo"},
							}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "include by collection and package name, exclude by package name",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"other"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.spam",
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"other"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.ham",
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"breakfast", "@foo"},
				Exclude: []string{"lunch"},
			},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{
								"code": "breakfast.spam", "collections": []string{"other"},
							}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{
								"code": "breakfast.ham", "collections": []string{"other"},
							}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "ignore unexpected collection type",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": 0,
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": false,
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures: []output.Result{
							{Metadata: map[string]any{
								"code": "breakfast.spam", "collections": []string{"foo"},
							}},
							{Metadata: map[string]any{
								"code": "lunch.spam",
							}},
						},
						Warnings: []output.Result{
							{Metadata: map[string]any{
								"code": "breakfast.ham", "collections": []string{"foo"},
							}},
							{Metadata: map[string]any{
								"code": "lunch.ham",
							}},
						},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "ignore unexpected code type",
			results: []output.CheckResult{
				{
					Failures: []output.Result{{Metadata: map[string]any{"code": 0}}},
					Warnings: []output.Result{{Metadata: map[string]any{"code": false}}},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures:   []output.Result{{Metadata: map[string]any{"code": 0}}},
						Warnings:   []output.Result{{Metadata: map[string]any{"code": false}}},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
		{
			name: "partial code",
			results: []output.CheckResult{
				{
					Failures: []output.Result{{Metadata: map[string]any{"code": 0}}},
					Warnings: []output.Result{{Metadata: map[string]any{"code": false}}},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{},
			want: CheckResults{
				{
					CheckResult: output.CheckResult{
						Failures:   []output.Result{{Metadata: map[string]any{"code": 0}}},
						Warnings:   []output.Result{{Metadata: map[string]any{"code": false}}},
						Skipped:    []output.Result{},
						Exceptions: []output.Result{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mockTestRunner{}
			dl := mockDownloader{}
			inputs := []string{"inputs"}
			ctx := setupTestContext(&r, &dl)
			r.On("Run", ctx, inputs).Return(tt.results, nil)

			p, err := policy.NewOfflinePolicy(ctx, policy.Now)
			assert.NoError(t, err)

			p = p.WithSpec(ecc.EnterpriseContractPolicySpec{
				Configuration: tt.config,
			})

			evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{
				testPolicySource{},
			}, p)

			assert.NoError(t, err)
			got, err := evaluator.Evaluate(ctx, inputs)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMakeMatchers(t *testing.T) {
	cases := []struct {
		name string
		code string
		term string
		want []string
	}{
		{name: "valid", code: "breakfast.spam", term: "eggs",
			want: []string{
				"breakfast", "breakfast.*", "breakfast.spam", "breakfast:eggs", "breakfast.*:eggs",
				"breakfast.spam:eggs", "*"}},
		{name: "valid without term", code: "breakfast.spam",
			want: []string{"breakfast", "breakfast.*", "breakfast.spam", "*"}},
		{name: "incomplete code", code: "spam", want: []string{"*"}},
		{name: "incomplete code with term", code: "spam", term: "eggs", want: []string{"*"}},
		{name: "extra code info ignored", code: "this.is.ignored.breakfast.spam",
			want: []string{"breakfast", "breakfast.*", "breakfast.spam", "*"}},
		{name: "empty code", code: "", want: []string{"*"}},
		{name: "empty code with term", code: "", term: "eggs", want: []string{"*"}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			result := output.Result{Metadata: map[string]any{}}
			if tt.code != "" {
				result.Metadata["code"] = tt.code
			}
			if tt.term != "" {
				result.Metadata["term"] = tt.term
			}
			assert.Equal(t, tt.want, makeMatchers(result))

		})
	}
}

func TestCollectAnnotationData(t *testing.T) {
	module := ast.MustParseModuleWithOpts(heredoc.Doc(`
		package a.b.c
		# METADATA
		# title: Title
		# description: Description
		# custom:
		#   short_name: short
		#   collections: [A, B, C]
		#   effective_on: 2022-01-01T00:00:00Z
		deny[msg] {
			msg := "hi"
		}`), ast.ParserOptions{
		ProcessAnnotation: true,
	})

	rules := policyRules{}
	rules.collect(ast.NewAnnotationsRef(module.Annotations[0]))

	assert.Equal(t, policyRules{
		"a.b.c.short": {
			Code:        "a.b.c.short",
			CodePackage: "a.b.c",
			Collections: []string{"A", "B", "C"},
			Description: "Description",
			EffectiveOn: "2022-01-01T00:00:00Z",
			Kind:        rule.Deny,
			Package:     "a.b.c",
			ShortName:   "short",
			Title:       "Title",
		},
	}, rules)
}

func TestRuleMetadata(t *testing.T) {
	effectiveOnTest := time.Now().Format(effectiveOnFormat)

	rules := policyRules{
		"warning1": rule.Info{
			Title: "Warning1",
		},
		"failure2": rule.Info{
			Title:       "Failure2",
			Description: "Failure 2 description",
		},
		"warning2": rule.Info{
			Title:       "Warning2",
			Description: "Warning 2 description",
			EffectiveOn: "2022-01-01T00:00:00Z",
		},
		"warning3": rule.Info{
			Title:       "Warning3",
			Description: "Warning 3 description",
			EffectiveOn: effectiveOnTest,
		},
	}
	cases := []struct {
		name   string
		result output.Result
		rules  policyRules
		code   string
		want   output.Result
	}{
		{
			name: "update title",
			result: output.Result{
				Metadata: map[string]any{
					"code":        "warning1",
					"collections": []any{"A"},
				},
			},
			rules: rules,
			code:  "warning1",
			want: output.Result{
				Metadata: map[string]any{
					"code":        "warning1",
					"collections": []string{"A"},
					"title":       "Warning1",
				},
			},
		},
		{
			name: "update title and description",
			result: output.Result{
				Metadata: map[string]any{
					"code":        "failure2",
					"collections": []any{"A"},
				},
			},
			rules: rules,
			code:  "failure2",
			want: output.Result{
				Metadata: map[string]any{
					"code":        "failure2",
					"collections": []string{"A"},
					"description": "Failure 2 description",
					"title":       "Failure2",
				},
			},
		},
		{
			name: "drop stale effectiveOn",
			result: output.Result{
				Metadata: map[string]any{
					"code":        "warning2",
					"collections": []any{"A"},
				},
			},
			rules: rules,
			code:  "warning2",
			want: output.Result{
				Metadata: map[string]any{
					"code":        "warning2",
					"collections": []string{"A"},
					"description": "Warning 2 description",
					"title":       "Warning2",
				},
			},
		},
		{
			name: "add relevant effectiveOn",
			result: output.Result{
				Metadata: map[string]any{
					"code":        "warning3",
					"collections": []any{"A"},
				},
			},
			rules: rules,
			code:  "warning3",
			want: output.Result{
				Metadata: map[string]any{
					"code":         "warning3",
					"collections":  []string{"A"},
					"description":  "Warning 3 description",
					"title":        "Warning3",
					"effective_on": effectiveOnTest,
				},
			},
		},
		{
			name: "rule not found",
			result: output.Result{
				Metadata: map[string]any{
					"collections": []any{"A"},
				},
			},
			rules: rules,
			code:  "",
			want: output.Result{
				Metadata: map[string]any{
					"collections": []any{"A"},
				},
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			rule, _ := addRuleMetadata(&tt.result, tt.rules)
			assert.Equal(t, rule, tt.code)
			assert.Equal(t, tt.result, tt.want)
		})
	}
}

func TestNameScoring(t *testing.T) {
	cases := []struct {
		name  string
		score int
	}{
		{
			name:  "*",
			score: 1,
		},
		{
			name:  "*:term", // corner case
			score: 101,
		},
		{
			name:  "*.rule:term", // corner case
			score: 201,
		},
		{
			name:  "pkg",
			score: 10,
		},
		{
			name:  "pkg.",
			score: 10,
		},
		{
			name:  "pkg.*",
			score: 10,
		},
		{
			name:  "pkg.rule",
			score: 110,
		},
		{
			name:  "pkg.:term",
			score: 110,
		},
		{
			name:  "pkg.*:term",
			score: 110,
		},
		{
			name:  "pkg:term",
			score: 110,
		},
		{
			name:  "pkg.rule:term",
			score: 210,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.score, score(c.name))
		})
	}
}
