// Copyright The Enterprise Contract Contributors
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
	"archive/tar"
	"context"
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/MakeNowJust/heredoc"
	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/open-policy-agent/opa/ast"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/kube-openapi/pkg/util/sets"

	"github.com/enterprise-contract/ec-cli/internal/downloader"
	"github.com/enterprise-contract/ec-cli/internal/opa/rule"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

type mockTestRunner struct {
	mock.Mock
}

func (m *mockTestRunner) Run(ctx context.Context, inputs []string) ([]Outcome, Data, error) {
	args := m.Called(ctx, inputs)

	return args.Get(0).([]Outcome), args.Get(1).(Data), args.Error(2)
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

func TestConftestEvaluatorEvaluateTimeBased(t *testing.T) {
	results := []Outcome{
		{
			Failures: []Result{
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
			Warnings: []Result{
				{
					Message: "existing warning",
					Metadata: map[string]any{
						"effective_on": "2021-01-01T00:00:00Z",
					},
				},
			},
		},
	}

	expectedResults := []Outcome{
		{
			Failures: []Result{
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
			Warnings: []Result{
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
			Skipped:    []Result{},
			Exceptions: []Result{},
		},
	}

	r := mockTestRunner{}

	dl := mockDownloader{}

	inputs := []string{"inputs"}

	expectedData := Data(map[string]any{
		"a": 1,
	})

	ctx := setupTestContext(&r, &dl)

	r.On("Run", ctx, inputs).Return(results, expectedData, nil)

	pol, err := policy.NewOfflinePolicy(ctx, policy.Now)
	assert.NoError(t, err)

	evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{
		testPolicySource{},
	}, pol, nil)

	assert.NoError(t, err)
	actualResults, data, err := evaluator.Evaluate(ctx, inputs)
	assert.NoError(t, err)
	assert.Equal(t, expectedResults, actualResults)
	assert.Equal(t, expectedData, data)
}

func setupTestContext(r *mockTestRunner, dl *mockDownloader) context.Context {
	ctx := withTestRunner(context.Background(), r)
	ctx = downloader.WithDownloadImpl(ctx, dl)
	fs := afero.NewMemMapFs()
	ctx = utils.WithFS(ctx, fs)
	ctx = withCapabilities(ctx, testCapabilities)

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

func TestConftestEvaluatorCapabilities(t *testing.T) {
	ctx := setupTestContext(nil, nil)
	fs := utils.FS(ctx)

	p, err := policy.NewOfflinePolicy(ctx, policy.Now)
	assert.NoError(t, err)

	evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{
		testPolicySource{},
	}, p, nil)
	assert.NoError(t, err)

	blob, err := afero.ReadFile(fs, evaluator.CapabilitiesPath())
	assert.NoError(t, err)
	var capabilities ast.Capabilities
	err = json.Unmarshal(blob, &capabilities)
	assert.NoError(t, err)

	defaultBuiltins := sets.NewString()
	for _, b := range ast.CapabilitiesForThisVersion().Builtins {
		defaultBuiltins.Insert(b.Name)
	}

	gotBuiltins := sets.NewString()
	for _, b := range capabilities.Builtins {
		gotBuiltins.Insert(b.Name)
	}

	expectedRemoved := sets.NewString("opa.runtime", "http.send", "net.lookup_ip_addr")

	assert.Equal(t, defaultBuiltins.Difference(gotBuiltins), expectedRemoved)

	assert.Equal(t, []string{""}, capabilities.AllowNet)
}
func TestConftestEvaluatorEvaluateNoSuccessWarningsOrFailures(t *testing.T) {
	results := []Outcome{
		{
			Failures:  []Result{},
			Warnings:  []Result{},
			Successes: []Result{},
		},
	}

	r := mockTestRunner{}

	dl := mockDownloader{}

	inputs := []string{"inputs"}

	ctx := setupTestContext(&r, &dl)

	r.On("Run", ctx, inputs).Return(results, Data(nil), nil)

	p, err := policy.NewOfflinePolicy(ctx, policy.Now)
	assert.NoError(t, err)

	evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{
		testPolicySource{},
	}, p, nil)

	assert.NoError(t, err)
	actualResults, data, err := evaluator.Evaluate(ctx, inputs)
	assert.ErrorContains(t, err, "no successes, warnings, or failures, check input")
	assert.Nil(t, actualResults)
	assert.Nil(t, data)
}

func TestConftestEvaluatorIncludeExclude(t *testing.T) {
	tests := []struct {
		name    string
		results []Outcome
		config  *ecc.EnterpriseContractPolicyConfiguration
		want    []Outcome
	}{
		{
			name: "exclude by package name",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "exclude by package name with wild card",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast.*"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "exclude by package and rule name",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Exclude: []string{"breakfast.spam", "lunch.ham"},
			},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "exclude by package name with term",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast:eggs"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "exclude by package name with wildcard and term",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast.*:eggs"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "exclude by package and rule name with term",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Exclude: []string{"breakfast.spam:eggs", "breakfast.ham:eggs"},
			},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "exclude by collection",
			results: []Outcome{
				{
					Failures: []Result{
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
					Warnings: []Result{
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
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []string{"bar"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.spam",
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []string{"bar"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.ham",
						}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by package",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by package with wildcard",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast.*"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by package and rule name with exclude wildcard",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "breakfast.eggs"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
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
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by package and rule name",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"breakfast.spam", "lunch.ham"},
			},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by package with term",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast:eggs"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by package with wildcard and term",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast.*:eggs"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by package and rule name with term",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
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
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by old-style collection",
			results: []Outcome{
				{
					Failures: []Result{
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
					Warnings: []Result{
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
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []string{"foo"},
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []string{"foo"},
						}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by collection",
			results: []Outcome{
				{
					Failures: []Result{
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
					Warnings: []Result{
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
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []string{"foo"},
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []string{"foo"},
						}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by collection and package",
			results: []Outcome{
				{
					Failures: []Result{
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
					Warnings: []Result{
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
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []string{"other"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []string{"foo"},
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []string{"other"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []string{"foo"},
						}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by collection and exclude by package",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []any{"foo"},
						}},
					},
					Warnings: []Result{
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
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []string{"foo"},
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []string{"foo"},
						}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by collection and package name, exclude by package name",
			results: []Outcome{
				{
					Failures: []Result{
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
					Warnings: []Result{
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
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []string{"other"},
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []string{"other"},
						}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "ignore unexpected collection type",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": 0,
						}},
					},
					Warnings: []Result{
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
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []string{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam",
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []string{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham",
						}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "ignore unexpected code type",
			results: []Outcome{
				{
					Failures: []Result{{Metadata: map[string]any{"code": 0}}},
					Warnings: []Result{{Metadata: map[string]any{"code": false}}},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{},
			want: []Outcome{
				{
					Failures:   []Result{{Metadata: map[string]any{"code": 0}}},
					Warnings:   []Result{{Metadata: map[string]any{"code": false}}},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "partial code",
			results: []Outcome{
				{
					Failures: []Result{{Metadata: map[string]any{"code": 0}}},
					Warnings: []Result{{Metadata: map[string]any{"code": false}}},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{},
			want: []Outcome{
				{
					Failures:   []Result{{Metadata: map[string]any{"code": 0}}},
					Warnings:   []Result{{Metadata: map[string]any{"code": false}}},
					Skipped:    []Result{},
					Exceptions: []Result{},
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
			r.On("Run", ctx, inputs).Return(tt.results, Data(nil), nil)

			p, err := policy.NewOfflinePolicy(ctx, policy.Now)
			assert.NoError(t, err)

			p = p.WithSpec(ecc.EnterpriseContractPolicySpec{
				Configuration: tt.config,
			})

			evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{
				testPolicySource{},
			}, p, nil)

			assert.NoError(t, err)
			got, data, err := evaluator.Evaluate(ctx, inputs)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, Data(nil), data)
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
			result := Result{Metadata: map[string]any{}}
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
		#   depends_on: a.b.c
		deny[msg] {
			msg := "hi"
		}`), ast.ParserOptions{
		ProcessAnnotation: true,
	})

	rules := policyRules{}
	require.NoError(t, rules.collect(ast.NewAnnotationsRef(module.Annotations[0])))

	assert.Equal(t, policyRules{
		"a.b.c.short": {
			Code:        "a.b.c.short",
			CodePackage: "a.b.c",
			Collections: []string{"A", "B", "C"},
			DependsOn:   []string{"a.b.c"},
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

	effectiveTimeTest := time.Now().Add(-24 * time.Hour)
	ctx := context.TODO()
	ctx = context.WithValue(ctx, effectiveTimeKey, effectiveTimeTest)

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
		result Result
		rules  policyRules
		want   Result
	}{
		{
			name: "update title",
			result: Result{
				Metadata: map[string]any{
					"code":        "warning1",
					"collections": []any{"A"},
				},
			},
			rules: rules,
			want: Result{
				Metadata: map[string]any{
					"code":        "warning1",
					"collections": []string{"A"},
					"title":       "Warning1",
				},
			},
		},
		{
			name: "update title and description",
			result: Result{
				Metadata: map[string]any{
					"code":        "failure2",
					"collections": []any{"A"},
				},
			},
			rules: rules,
			want: Result{
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
			result: Result{
				Metadata: map[string]any{
					"code":        "warning2",
					"collections": []any{"A"},
				},
			},
			rules: rules,
			want: Result{
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
			result: Result{
				Metadata: map[string]any{
					"code":        "warning3",
					"collections": []any{"A"},
				},
			},
			rules: rules,
			want: Result{
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
			result: Result{
				Metadata: map[string]any{
					"collections": []any{"A"},
				},
			},
			rules: rules,
			want: Result{
				Metadata: map[string]any{
					"collections": []any{"A"},
				},
			},
		},
	}
	for i, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			addRuleMetadata(ctx, &cases[i].result, tt.rules)
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

func TestCheckResultsTrim(t *testing.T) {
	cases := []struct {
		name     string
		given    []Outcome
		expected []Outcome
	}{
		{
			name: "simple dependency",
			given: []Outcome{
				{
					Failures: []Result{
						{
							Message: "failure 1",
							Metadata: map[string]interface{}{
								metadataCode: "a.failure1",
							},
						},
					},
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode:      "a.success1",
								metadataDependsOn: []string{"a.failure1"},
							},
						},
					},
				},
			},
			expected: []Outcome{
				{
					Failures: []Result{
						{
							Message: "failure 1",
							Metadata: map[string]interface{}{
								metadataCode: "a.failure1",
							},
						},
					},
					Successes: []Result{},
				},
			},
		},
		{
			name: "successful dependants are not trimmed",
			given: []Outcome{
				{
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode: "a.success1",
							},
						},
					},
				},
				{
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode:      "a.success2",
								metadataDependsOn: []string{"a.success1"},
							},
						},
					},
				},
			},
			expected: []Outcome{
				{
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode: "a.success1",
							},
						},
					},
				},
				{
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode:      "a.success2",
								metadataDependsOn: []string{"a.success1"},
							},
						},
					},
				},
			},
		},
		{
			name: "failures, warnings and successes with dependencies",
			given: []Outcome{
				{
					Failures: []Result{
						{
							Message: "Fails",
							Metadata: map[string]interface{}{
								metadataCode: "a.failure",
							},
						},
						{
							Message: "Fails and depends",
							Metadata: map[string]interface{}{
								metadataCode:      "a.failure",
								metadataDependsOn: []string{"a.failure"},
							},
						},
					},
					Warnings: []Result{
						{
							Message: "Warning",
							Metadata: map[string]interface{}{
								metadataCode:      "a.warning",
								metadataDependsOn: []string{"a.failure"},
							},
						},
					},
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode:      "a.success",
								metadataDependsOn: []string{"a.failure"},
							},
						},
					},
				},
			},
			expected: []Outcome{
				{
					Failures: []Result{
						{
							Message: "Fails",
							Metadata: map[string]interface{}{
								metadataCode: "a.failure",
							},
						},
					},
					Warnings:  []Result{},
					Successes: []Result{},
				},
			},
		},
		{
			name: "unrelated dependency",
			given: []Outcome{
				{
					Failures: []Result{
						{
							Message: "failure 1",
							Metadata: map[string]interface{}{
								metadataCode: "a.failure",
							},
						},
					},
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode:      "a.success1",
								metadataDependsOn: []string{"a.unrelated"},
							},
						},
					},
				},
			},
			expected: []Outcome{
				{
					Failures: []Result{
						{
							Message: "failure 1",
							Metadata: map[string]interface{}{
								metadataCode: "a.failure",
							},
						},
					},
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode:      "a.success1",
								metadataDependsOn: []string{"a.unrelated"},
							},
						},
					},
				},
			},
		},
	}

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			trim(&cases[i].given)
			assert.Equal(t, c.expected, c.given)
		})
	}
}

//go:embed __testdir__/*/*.rego
var policies embed.FS

func TestConftestEvaluatorEvaluate(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(path.Join(dir, "inputs"), 0755))
	require.NoError(t, os.WriteFile(path.Join(dir, "inputs", "data.json"), []byte("{}"), 0600))

	rego, err := fs.Sub(policies, "__testdir__/simple")
	require.NoError(t, err)

	rules, err := rulesArchive(t, rego)
	require.NoError(t, err)

	ctx := withCapabilities(context.Background(), testCapabilities)

	p, err := policy.NewOfflinePolicy(ctx, "2014-05-31")
	require.NoError(t, err)

	p = p.WithSpec(ecc.EnterpriseContractPolicySpec{
		Configuration: &ecc.EnterpriseContractPolicyConfiguration{},
	})

	evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{
		&source.PolicyUrl{
			Url:  rules,
			Kind: source.PolicyKind,
		},
	}, p, nil)
	require.NoError(t, err)

	results, data, err := evaluator.Evaluate(ctx, []string{path.Join(dir, "inputs")})
	require.NoError(t, err)

	// sort the slice by code for test stability
	sort.Slice(results, func(l, r int) bool {
		return strings.Compare(results[l].Namespace, results[r].Namespace) < 0
	})

	for i := range results {
		// let's not fail the snapshot on different locations of $TMPDIR
		results[i].FileName = filepath.ToSlash(strings.Replace(results[i].FileName, dir, "$TMPDIR", 1))
		// sort the slice by code for test stability
		sort.Slice(results[i].Successes, func(l, r int) bool {
			return strings.Compare(results[i].Successes[l].Metadata[metadataCode].(string), results[i].Successes[r].Metadata[metadataCode].(string)) < 0
		})
	}

	snaps.MatchSnapshot(t, results, data)
}

func TestUnconformingRule(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(path.Join(dir, "inputs"), 0755))
	require.NoError(t, os.WriteFile(path.Join(dir, "inputs", "data.json"), []byte("{}"), 0600))

	rego, err := fs.Sub(policies, "__testdir__/unconforming")
	require.NoError(t, err)

	rules, err := rulesArchive(t, rego)
	require.NoError(t, err)

	ctx := context.Background()

	p, err := policy.NewInertPolicy(ctx, "")
	require.NoError(t, err)

	evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{
		&source.PolicyUrl{
			Url:  rules,
			Kind: source.PolicyKind,
		},
	}, p, nil)
	require.NoError(t, err)

	_, _, err = evaluator.Evaluate(ctx, []string{path.Join(dir, "inputs")})
	assert.EqualError(t, err, `the rule "deny = true { true }" returns an unsupported value, at no_msg.rego:3`)
}

func TestNewConftestEvaluatorComputeIncludeExclude(t *testing.T) {
	cases := []struct {
		name            string
		globalConfig    *ecc.EnterpriseContractPolicyConfiguration
		sourceConfig    *ecc.SourceConfig
		expectedInclude []string
		expectedExclude []string
	}{
		{name: "no config", expectedInclude: []string{"*"}},
		{
			name:            "empty global config",
			globalConfig:    &ecc.EnterpriseContractPolicyConfiguration{},
			expectedInclude: []string{"*"},
		},
		{
			name: "global config",
			globalConfig: &ecc.EnterpriseContractPolicyConfiguration{
				Include:     []string{"include-me"},
				Exclude:     []string{"exclude-me"},
				Collections: []string{"collect-me"},
			},
			expectedInclude: []string{"include-me", "@collect-me"},
			expectedExclude: []string{"exclude-me"},
		},
		{
			name:            "empty source config",
			sourceConfig:    &ecc.SourceConfig{},
			expectedInclude: []string{"*"},
		},
		{
			name: "source config",
			sourceConfig: &ecc.SourceConfig{
				Include: []string{"include-me"},
				Exclude: []string{"exclude-me"},
			},
			expectedInclude: []string{"include-me"},
			expectedExclude: []string{"exclude-me"},
		},
		{
			name: "source config over global config",
			globalConfig: &ecc.EnterpriseContractPolicyConfiguration{
				Include:     []string{"include-ignored"},
				Exclude:     []string{"exclude-ignored"},
				Collections: []string{"collection-ignored"},
			},
			sourceConfig: &ecc.SourceConfig{
				Include: []string{"include-me"},
				Exclude: []string{"exclude-me"},
			},
			expectedInclude: []string{"include-me"},
			expectedExclude: []string{"exclude-me"},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			ctx := withCapabilities(context.Background(), testCapabilities)

			p, err := policy.NewOfflinePolicy(ctx, "2014-05-31")
			require.NoError(t, err)

			p = p.WithSpec(ecc.EnterpriseContractPolicySpec{
				Configuration: tt.globalConfig,
			})

			evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{
				&source.PolicyUrl{
					Url:  path.Join(dir, "policy", "rules.tar"),
					Kind: source.PolicyKind,
				},
			}, p, tt.sourceConfig)
			require.NoError(t, err)

			ce := evaluator.(conftestEvaluator)
			require.Equal(t, tt.expectedInclude, ce.include)
			require.Equal(t, tt.expectedExclude, ce.exclude)
		})
	}

}

var testCapabilities string

func init() {
	// Given the amount of tests in this file, creating the capabilities string
	// can add significant overhead. We do it here once for all the tests instead.
	data, err := strictCapabilities(context.Background())
	if err != nil {
		panic(err)
	}
	testCapabilities = data
}

func rulesArchive(t *testing.T, files fs.FS) (string, error) {
	t.Helper()

	dir := t.TempDir()

	rules := path.Join(dir, "rules.tar")

	f, err := os.Create(rules)
	if err != nil {
		return "", err
	}
	defer f.Close()
	ar := tar.NewWriter(f)
	defer ar.Close()

	rego, err := fs.ReadDir(files, ".")
	if err != nil {
		return "", err
	}

	for _, r := range rego {
		if r.IsDir() {
			continue
		}
		f, err := files.Open(r.Name())
		if err != nil {
			return "", err
		}

		bytes, err := io.ReadAll(f)
		if err != nil {
			return "", err
		}

		require.NoError(t, ar.WriteHeader(&tar.Header{
			Name: r.Name(),
			Mode: 0644,
			Size: int64(len(bytes)),
		}))

		if _, err = ar.Write(bytes); err != nil {
			return "", err
		}
	}

	return rules, nil
}
