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
	"fmt"
	"reflect"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/hacbs-contract/ec-cli/internal/utils"
	"github.com/open-policy-agent/conftest/runner"
	"github.com/spf13/afero"
)

func checkoutRepoMock(_ string, _ bool, _ *git.CloneOptions) (*git.Repository, error) {
	return &git.Repository{}, nil
}

func checkoutRepoFailureMock(_ string, _ bool, _ *git.CloneOptions) (*git.Repository, error) {
	return nil, fmt.Errorf("unable to checkout repo")
}

func createWorkDirMock(_ afero.Fs, _ string, _ string) (string, error) {
	_ = utils.AppFS.MkdirAll("/tmp/ec-work-1234", 0755)
	return "/tmp/ec-work-1234", nil
}

func createWorkDirFailMock(_ afero.Fs, _ string, _ string) (string, error) {
	return "", fmt.Errorf("unable to create work dir")
}

func TestEvaluator_addDataPath(t *testing.T) {
	utils.AppFS = afero.NewMemMapFs()
	type fields struct {
		Context       context.Context
		Target        EvaluationTarget
		PolicySources []PolicySource
		Paths         ConfigurationPaths
		TestRunner    runner.TestRunner
		Namespace     []string
		OutputFormat  string
		workDir       string
	}
	tests := []struct {
		name    string
		fields  fields
		want    []string
		wantErr bool
	}{
		{
			name: "Adds data path",
			fields: fields{
				workDir: "/tmp/ec-work-1234",
			},
			want:    []string{"/tmp/ec-work-1234/data"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Evaluator{
				Context:       tt.fields.Context,
				Target:        tt.fields.Target,
				PolicySources: tt.fields.PolicySources,
				Paths:         tt.fields.Paths,
				TestRunner:    tt.fields.TestRunner,
				Namespace:     tt.fields.Namespace,
				OutputFormat:  tt.fields.OutputFormat,
				workDir:       tt.fields.workDir,
			}
			err := e.addDataPath()
			got := e.Paths.DataPaths
			if (err != nil) != tt.wantErr {
				t.Errorf("addDataPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, e.Paths.DataPaths) {
				t.Errorf("addDataPath() got =%v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluator_addPolicyPaths(t *testing.T) {
	type fields struct {
		Context       context.Context
		Target        EvaluationTarget
		PolicySources []PolicySource
		Paths         ConfigurationPaths
		TestRunner    runner.TestRunner
		Namespace     []string
		OutputFormat  string
		workDir       string
	}
	tests := []struct {
		name    string
		fields  fields
		want    []string
		wantErr bool
	}{
		{
			name: "Adds policy path",
			fields: fields{
				workDir: "/tmp/ec-work-1234",
				PolicySources: []PolicySource{
					&PolicyRepo{
						PolicyDir: "policies",
						RepoURL:   "https://example.com/user/foo.git",
						RepoRef:   "main",
					},
				},
			},
			want:    []string{"/tmp/ec-work-1234/policies"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			CheckoutRepo = checkoutRepoMock
			e := &Evaluator{
				Context:       tt.fields.Context,
				Target:        tt.fields.Target,
				PolicySources: tt.fields.PolicySources,
				Paths:         tt.fields.Paths,
				TestRunner:    tt.fields.TestRunner,
				Namespace:     tt.fields.Namespace,
				OutputFormat:  tt.fields.OutputFormat,
				workDir:       tt.fields.workDir,
			}
			err := e.addPolicyPaths()
			got := e.Paths.PolicyPaths
			if (err != nil) != tt.wantErr {
				t.Errorf("addPolicyPaths() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, e.Paths.PolicyPaths) {
				t.Errorf("addPolicyPaths() got =%v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluator_createWorkDir(t *testing.T) {
	createWorkDir = func(_ afero.Fs, _, _ string) (name string, err error) {
		return "/tmp/ec-work-1234", nil
	}
	type fields struct {
		Context       context.Context
		Target        EvaluationTarget
		PolicySources []PolicySource
		Paths         ConfigurationPaths
		TestRunner    runner.TestRunner
		Namespace     []string
		OutputFormat  string
		workDir       string
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name:    "Creates work dir",
			fields:  fields{},
			want:    "/tmp/ec-work-1234",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			utils.AppFS = afero.NewMemMapFs()
			e := &Evaluator{
				Context:       tt.fields.Context,
				Target:        tt.fields.Target,
				PolicySources: tt.fields.PolicySources,
				Paths:         tt.fields.Paths,
				TestRunner:    tt.fields.TestRunner,
				Namespace:     tt.fields.Namespace,
				OutputFormat:  tt.fields.OutputFormat,
				workDir:       tt.fields.workDir,
			}
			got, err := e.createWorkDir()
			if (err != nil) != tt.wantErr {
				t.Errorf("createWorkDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("createWorkDir() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewPipelineEvaluator(t *testing.T) {
	type args struct {
		ctx        context.Context
		fpath      string
		policyRepo PolicyRepo
		namespace  string
	}
	tests := []struct {
		name         string
		args         args
		want         *Evaluator
		wantErr      bool
		errMsg       error
		failurePoint string
	}{
		{
			name: "Returns evaluator with appropriate inputs",
			args: args{
				ctx:   context.Background(),
				fpath: "/tmp/pipeline.json",
				policyRepo: PolicyRepo{
					PolicyDir: "policy",
					RepoURL:   "https://example.com/user/foo.git",
					RepoRef:   "main",
				},
				namespace: "pipeline.main",
			},
			want: &Evaluator{
				Context: context.Background(),
				Target: &DefinitionFile{
					fpath: "/tmp/pipeline.json",
					name:  "",
				},
				PolicySources: []PolicySource{&PolicyRepo{
					PolicyDir: "policy",
					RepoURL:   "https://example.com/user/foo.git",
					RepoRef:   "main",
				}},
				Paths: ConfigurationPaths{
					PolicyPaths: []string{"/tmp/ec-work-1234/policy"},
					DataPaths:   []string{"/tmp/ec-work-1234/data"},
				},
				TestRunner: runner.TestRunner{
					Policy:    []string{"/tmp/ec-work-1234/policy"},
					Data:      []string{"/tmp/ec-work-1234/data"},
					Namespace: []string{"pipeline.main"},
					NoFail:    true,
					Output:    "json",
				},
				Namespace:    []string{"pipeline.main"},
				OutputFormat: "json",
				workDir:      "/tmp/ec-work-1234",
			},
		},
		{
			name: "Returns error when fpath doesn't exist",
			args: args{
				ctx:   context.Background(),
				fpath: "/tmp/non-existent-pipeline.json",
				policyRepo: PolicyRepo{
					PolicyDir: "policy",
					RepoURL:   "https://example.com/user/foo.git",
					RepoRef:   "main",
				},
				namespace: "pipeline.main",
			},
			wantErr:      true,
			failurePoint: "fpath",
			errMsg:       fmt.Errorf("definition file `/tmp/non-existent-pipeline.json` does not exist"),
		},
		{
			name: "Returns error when createWorkDir fails",
			args: args{
				ctx:   context.Background(),
				fpath: "/tmp/pipeline.json",
				policyRepo: PolicyRepo{
					PolicyDir: "policy",
					RepoURL:   "https://example.com/user/foo.git",
					RepoRef:   "main",
				},
				namespace: "pipeline.main",
			},
			wantErr:      true,
			failurePoint: "createWorkDir",
			errMsg:       fmt.Errorf("unable to create work dir"),
		},
		{
			name: "Returns error when addPolicyPaths fails",
			args: args{
				ctx:   context.Background(),
				fpath: "/tmp/pipeline.json",
				policyRepo: PolicyRepo{
					PolicyDir: "policy",
					RepoURL:   "https://example.com/user/foo.git",
					RepoRef:   "main",
				},
				namespace: "pipeline.main",
			},
			wantErr:      true,
			failurePoint: "addPolicyPaths",
			errMsg:       fmt.Errorf("unable to checkout repo"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			utils.AppFS = afero.NewMemMapFs()
			switch tt.failurePoint {
			case "fpath":
				tt.args.fpath = "/tmp/non-existent-pipeline.json"
				createWorkDir = createWorkDirMock
			case "createWorkDir":
				createWorkDir = createWorkDirFailMock
				_ = deployPipelineFile()

			case "addPolicyPaths":
				createWorkDir = createWorkDirMock
				_ = deployPipelineFile()
				CheckoutRepo = checkoutRepoFailureMock
			default:
				createWorkDir = createWorkDirMock
				_ = deployPipelineFile()
				CheckoutRepo = checkoutRepoMock

			}
			got, err := NewPipelineEvaluator(tt.args.ctx, tt.args.fpath, tt.args.policyRepo, tt.args.namespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewPipelineEvaluator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(err, tt.errMsg) {
				t.Errorf("NewPipelineEvaluator() got = %v, want %v", err, tt.errMsg)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewPipelineEvaluator() got = %v, want %v", got, tt.want)
			}
		})
	}
}
