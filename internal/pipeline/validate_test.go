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

package pipeline

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hacbs-contract/ec-cli/internal/evaluation_target/pipeline_definition_file"
	"github.com/hacbs-contract/ec-cli/internal/output"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
	conftestout "github.com/open-policy-agent/conftest/output"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

type mockEvaluator struct{}
type badMockEvaluator struct{}

func (e mockEvaluator) Evaluate(ctx context.Context, inputs []string) ([]conftestout.CheckResult, error) {
	return []conftestout.CheckResult{}, nil
}

func (b badMockEvaluator) Evaluate(ctx context.Context, inputs []string) ([]conftestout.CheckResult, error) {
	return nil, errors.New("Evaluator error")
}

func mockNewPipelineDefinitionFile(ctx context.Context, fs afero.Fs, fpath string, sources []source.PolicySource, namespace string) (*pipeline_definition_file.DefinitionFile, error) {
	if fpath == "good" {
		return &pipeline_definition_file.DefinitionFile{
			Evaluator: mockEvaluator{},
		}, nil

	}
	return nil, fmt.Errorf("fpath '%s' does not exist", fpath)
}

func badMockNewPipelineDefinitionFile(ctx context.Context, fs afero.Fs, fpath string, sources []source.PolicySource, namespace string) (*pipeline_definition_file.DefinitionFile, error) {
	return &pipeline_definition_file.DefinitionFile{
		Evaluator: badMockEvaluator{},
	}, nil
}

func Test_ValidatePipeline(t *testing.T) {
	tests := []struct {
		name    string
		fpath   string
		err     error
		output  *output.Output
		defFunc func(ctx context.Context, fs afero.Fs, fpath string, sources []source.PolicySource, namespace string) (*pipeline_definition_file.DefinitionFile, error)
	}{
		{
			name:    "validation succeeds",
			fpath:   "good",
			err:     nil,
			output:  &output.Output{PolicyCheck: []conftestout.CheckResult{}},
			defFunc: mockNewPipelineDefinitionFile,
		},
		{
			name:    "validation fails on bad path",
			fpath:   "bad",
			err:     fmt.Errorf("fpath '%s' does not exist", "bad"),
			output:  nil,
			defFunc: mockNewPipelineDefinitionFile,
		},
		{
			name:    "evaluator fails",
			fpath:   "good",
			err:     errors.New("Evaluator error"),
			output:  nil,
			defFunc: badMockNewPipelineDefinitionFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline_def_file = tt.defFunc
			output, err := ValidatePipeline(context.TODO(), afero.NewOsFs(), tt.fpath, []source.PolicySource{}, "namespace")
			assert.Equal(t, tt.err, err)
			assert.Equal(t, tt.output, output)
		})
	}
}
