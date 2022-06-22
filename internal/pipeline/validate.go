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
	"github.com/open-policy-agent/conftest/runner"
)

//ValidatePipeline takes the required inputs to create an evaluator object,
//validates the required aspects, creates necessary paths, gets the necessary
//policies, creates a Conftest Test Runner, executes the test against the
//provided policies, and displays the output.
func ValidatePipeline(ctx context.Context, fpath string, policyRepo PolicyRepo, namespace string) error {
	e := &Evaluator{
		Context:       ctx,
		Target:        &DefinitionFile{fpath: fpath},
		Paths:         ConfigurationPaths{},
		PolicySources: []PolicySource{&policyRepo},
		Namespace:     []string{namespace},
	}
	_, err := e.Target.exists()
	if err != nil {
		return err
	}

	workDir, err := e.createWorkDir()
	if err != nil {
		return err
	}
	e.workDir = workDir

	err = e.addPolicyPaths()
	if err != nil {
		return err
	}

	err = e.addDataPath()
	if err != nil {
		return err
	}

	e.TestRunner = runner.TestRunner{
		Policy:    e.Paths.PolicyPaths,
		Data:      e.Paths.DataPaths,
		Namespace: e.Namespace,
		NoFail:    true,
		Output:    e.OutputFormat,
	}

	results, err := e.TestRunner.Run(ctx, []string{fpath})
	if err != nil {
		return err
	}
	out := &policy.Output{PolicyCheck: results}
	err = out.Print()
	if err != nil {
		return err
	}
	return nil
}
