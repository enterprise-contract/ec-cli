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

	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/open-policy-agent/conftest/output"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/hacbs-contract/ec-cli/internal/downloader"
	"github.com/hacbs-contract/ec-cli/internal/policy"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
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
	return "test-policy-path", nil
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

	r := mockTestRunner{}

	dl := mockDownloader{}

	inputs := []string{"inputs"}

	ctx := downloader.WithDownloadImpl(withTestRunner(context.Background(), &r), &dl)

	r.On("Run", ctx, inputs).Return(results, nil)

	pol, err := policy.NewOfflinePolicy(ctx, policy.Now)
	assert.NoError(t, err)

	evaluator, err := NewConftestEvaluator(ctx, afero.NewMemMapFs(), []source.PolicySource{
		testPolicySource{},
	}, pol)

	assert.NoError(t, err)
	actualResults, err := evaluator.Evaluate(ctx, inputs)
	assert.NoError(t, err)
	assert.Equal(t, expectedResults, actualResults)
}

func TestConftestEvaluatorIncludeExclude(t *testing.T) {
	tests := []struct {
		name    string
		results []output.CheckResult
		config  *ecc.EnterpriseContractPolicyConfiguration
		want    []output.CheckResult
	}{
		{
			name: "exclude by package name",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{"code": "breakfast.spam"}},
						{Metadata: map[string]interface{}{"code": "lunch.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{"code": "breakfast.ham"}},
						{Metadata: map[string]interface{}{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast"}},
			want: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{"code": "lunch.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{"code": "lunch.ham"}},
					},
				},
			},
		},
		{
			name: "exclude by package and rule name",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{"code": "breakfast.spam"}},
						{Metadata: map[string]interface{}{"code": "lunch.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{"code": "breakfast.ham"}},
						{Metadata: map[string]interface{}{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Exclude: []string{"breakfast.spam", "lunch.ham"},
			},
			want: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{"code": "lunch.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{"code": "breakfast.ham"}},
					},
				},
			},
		},
		{
			name: "include by package",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{"code": "breakfast.spam"}},
						{Metadata: map[string]interface{}{"code": "lunch.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{"code": "breakfast.ham"}},
						{Metadata: map[string]interface{}{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast"}},
			want: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{"code": "breakfast.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{"code": "breakfast.ham"}},
					},
				},
			},
		},
		{
			name: "include by package and rule name",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{"code": "breakfast.spam"}},
						{Metadata: map[string]interface{}{"code": "lunch.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{"code": "breakfast.ham"}},
						{Metadata: map[string]interface{}{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"breakfast.spam", "lunch.ham"},
			},
			want: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{"code": "breakfast.spam"}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{"code": "lunch.ham"}},
					},
				},
			},
		},
		{
			name: "filter by collection",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.spam", "collections": []interface{}{"foo"},
						}},
						{Metadata: map[string]interface{}{
							// Different collection
							"code": "lunch.spam", "collections": []interface{}{"bar"},
						}},
						{Metadata: map[string]interface{}{
							// No collections at all
							"code": "dinner.spam",
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.ham", "collections": []interface{}{"foo"},
						}},
						{Metadata: map[string]interface{}{
							// Different collection
							"code": "lunch.ham", "collections": []interface{}{"bar"},
						}},
						{Metadata: map[string]interface{}{
							// No collections at all
							"code": "dinner.ham",
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Collections: []string{"foo"}},
			want: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.spam", "collections": []interface{}{"foo"},
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.ham", "collections": []interface{}{"foo"},
						}},
					},
				},
			},
		},
		{
			name: "filter by collection with include",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.spam", "collections": []interface{}{"foo"},
						}},
						{Metadata: map[string]interface{}{
							"code": "lunch.spam", "collections": []interface{}{"foo"},
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.ham", "collections": []interface{}{"foo"},
						}},
						{Metadata: map[string]interface{}{
							"code": "lunch.ham", "collections": []interface{}{"foo"},
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Collections: []string{"foo"},
				Include:     []string{"breakfast"},
			},
			want: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.spam", "collections": []interface{}{"foo"},
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.ham", "collections": []interface{}{"foo"},
						}},
					},
				},
			},
		},
		{
			name: "filter by collection with exclude",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.spam", "collections": []interface{}{"foo"},
						}},
						{Metadata: map[string]interface{}{
							"code": "lunch.spam", "collections": []interface{}{"foo"},
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.ham", "collections": []interface{}{"foo"},
						}},
						{Metadata: map[string]interface{}{
							"code": "lunch.ham", "collections": []interface{}{"foo"},
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Collections: []string{"foo"},
				Exclude:     []string{"lunch"},
			},
			want: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.spam", "collections": []interface{}{"foo"},
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.ham", "collections": []interface{}{"foo"},
						}},
					},
				},
			},
		},
		{
			name: "ignore unexpected collection type",
			results: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.spam", "collections": []interface{}{"foo"},
						}},
						{Metadata: map[string]interface{}{
							"code": "lunch.spam", "collections": 0,
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.ham", "collections": []interface{}{"foo"},
						}},
						{Metadata: map[string]interface{}{
							"code": "lunch.ham", "collections": false,
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{},
			want: []output.CheckResult{
				{
					Failures: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.spam", "collections": []interface{}{"foo"},
						}},
						{Metadata: map[string]interface{}{
							"code": "lunch.spam", "collections": 0,
						}},
					},
					Warnings: []output.Result{
						{Metadata: map[string]interface{}{
							"code": "breakfast.ham", "collections": []interface{}{"foo"},
						}},
						{Metadata: map[string]interface{}{
							"code": "lunch.ham", "collections": false,
						}},
					},
				},
			},
		},
		{
			name: "ignore unexpected code type",
			results: []output.CheckResult{
				{
					Failures: []output.Result{{Metadata: map[string]interface{}{"code": 0}}},
					Warnings: []output.Result{{Metadata: map[string]interface{}{"code": false}}},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{},
			want: []output.CheckResult{
				{
					Failures: []output.Result{{Metadata: map[string]interface{}{"code": 0}}},
					Warnings: []output.Result{{Metadata: map[string]interface{}{"code": false}}},
				},
			},
		},
		{
			name: "partial code",
			results: []output.CheckResult{
				{
					Failures: []output.Result{{Metadata: map[string]interface{}{"code": 0}}},
					Warnings: []output.Result{{Metadata: map[string]interface{}{"code": false}}},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{},
			want: []output.CheckResult{
				{
					Failures: []output.Result{{Metadata: map[string]interface{}{"code": 0}}},
					Warnings: []output.Result{{Metadata: map[string]interface{}{"code": false}}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mockTestRunner{}
			dl := mockDownloader{}
			inputs := []string{"inputs"}
			ctx := downloader.WithDownloadImpl(withTestRunner(context.Background(), &r), &dl)
			r.On("Run", ctx, inputs).Return(tt.results, nil)

			p, err := policy.NewOfflinePolicy(ctx, policy.Now)
			assert.NoError(t, err)

			p = p.WithSpec(ecc.EnterpriseContractPolicySpec{
				Configuration: tt.config,
			})

			evaluator, err := NewConftestEvaluator(ctx, afero.NewMemMapFs(), []source.PolicySource{
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
		want []string
	}{
		{name: "valid", code: "breakfast.spam", want: []string{"*", "breakfast", "breakfast.spam"}},
		{name: "incomplete code", code: "spam", want: []string{"*"}},
		{name: "extra code info ignored", code: "this.is.ignored.breakfast.spam",
			want: []string{"*", "breakfast", "breakfast.spam"}},
		{name: "empty code", code: "", want: []string{"*"}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, makeMatchers(tt.code))

		})
	}
}
