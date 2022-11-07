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
	"regexp"
	"testing"

	"github.com/open-policy-agent/conftest/output"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/hacbs-contract/ec-cli/internal/downloader"
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

	workDirData := regexp.MustCompile(`/tmp/ec-work-\d+/data`)
	// download of hardcoded data
	dl.On("Download", ctx, mock.MatchedBy(workDirData.MatchString), []string{hardCodedRequiredData}).Return(nil)

	evaluator, err := NewConftestEvaluator(ctx, afero.NewMemMapFs(), []source.PolicySource{
		testPolicySource{},
	}, "release.main", nil)

	assert.NoError(t, err)
	actualResults, err := evaluator.Evaluate(ctx, inputs)
	assert.NoError(t, err)
	assert.Equal(t, expectedResults, actualResults)
}
