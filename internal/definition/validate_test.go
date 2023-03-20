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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package definition

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/evaluation_target/definition"
	"github.com/hacbs-contract/ec-cli/internal/evaluator"
	"github.com/hacbs-contract/ec-cli/internal/output"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
	"github.com/hacbs-contract/ec-cli/internal/utils"
)

type mockEvaluator struct{}
type badMockEvaluator struct{}

func (e mockEvaluator) Evaluate(ctx context.Context, inputs []string) (evaluator.CheckResults, error) {
	return evaluator.CheckResults{}, nil
}

func (e mockEvaluator) Destroy() {
}

func (b badMockEvaluator) Evaluate(ctx context.Context, inputs []string) (evaluator.CheckResults, error) {
	return nil, errors.New("Evaluator error")
}

func (e badMockEvaluator) Destroy() {
}

func mockNewPipelineDefinitionFile(ctx context.Context, fpath []string, sources []source.PolicySource, namespace []string) (*definition.Definition, error) {
	return &definition.Definition{
		Evaluator: mockEvaluator{},
	}, nil
}

func badMockNewPipelineDefinitionFile(ctx context.Context, fpath []string, sources []source.PolicySource, namespace []string) (*definition.Definition, error) {
	return &definition.Definition{
		Evaluator: badMockEvaluator{},
	}, nil
}

func Test_ValidatePipeline(t *testing.T) {
	tests := []struct {
		name    string
		fpath   string
		err     error
		output  *output.Output
		defFunc func(ctx context.Context, fpath []string, sources []source.PolicySource, namespace []string) (*definition.Definition, error)
	}{
		{
			name:    "validation succeeds",
			fpath:   "/blah",
			err:     nil,
			output:  &output.Output{PolicyCheck: evaluator.CheckResults{}},
			defFunc: mockNewPipelineDefinitionFile,
		},
		{
			name:    "validation fails on bad path",
			fpath:   "bad",
			err:     fmt.Errorf("unable to parse the provided definition file: %v", "bad"),
			output:  nil,
			defFunc: mockNewPipelineDefinitionFile,
		},
		{
			name:    "valid file, but evaluator fails",
			fpath:   "/blah",
			err:     errors.New("Evaluator error"),
			output:  nil,
			defFunc: badMockNewPipelineDefinitionFile,
		},
		{
			name:    "validation succeeds with json input",
			fpath:   "{\"json\": 1}",
			err:     nil,
			output:  &output.Output{PolicyCheck: evaluator.CheckResults{}},
			defFunc: mockNewPipelineDefinitionFile,
		},
		{
			name:    "validation succeeds with yaml input",
			fpath:   "kind: task",
			err:     nil,
			output:  &output.Output{PolicyCheck: evaluator.CheckResults{}},
			defFunc: mockNewPipelineDefinitionFile,
		},
		{
			name:    "validation fails with only an array of strings as yaml",
			fpath:   "- test1\n- test2",
			err:     fmt.Errorf("unable to parse the provided definition file: %v", "- test1\n- test2"),
			output:  nil,
			defFunc: mockNewPipelineDefinitionFile,
		},
	}

	appFS := afero.NewMemMapFs()
	//err := appFS.MkdirAll("/blah", 0777)
	err := afero.WriteFile(appFS, "/blah", []byte("data"), 0777)
	assert.NoError(t, err)
	ctx := utils.WithFS(context.Background(), appFS)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			definitionFile = tt.defFunc
			output, err := ValidateDefinition(ctx, tt.fpath, []source.PolicySource{}, []string{})
			assert.Equal(t, tt.err, err)
			assert.Equal(t, tt.output, output)
		})
	}
}
