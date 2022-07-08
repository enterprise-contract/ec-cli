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
	"path/filepath"

	"github.com/open-policy-agent/conftest/runner"
	"github.com/spf13/afero"

	"github.com/hacbs-contract/ec-cli/internal/policy/source"
	"github.com/hacbs-contract/ec-cli/internal/utils"
)

//CreateWorkDir is a var which can be overwritten in testing.
var CreateWorkDir = afero.TempDir

// ConftestEvaluator represents a structure which can be used to evaluate targets
type ConftestEvaluator struct {
	Context       context.Context
	PolicySources []source.PolicySource
	Paths         ConfigurationPaths
	TestRunner    runner.TestRunner
	Namespace     []string
	OutputFormat  string
	WorkDir       string
}

//ConfigurationPaths is a structs containing necessary paths for an Evaluator struct
type ConfigurationPaths struct {
	PolicyPaths []string
	DataPaths   []string
}

// NewConftestEvaluator returns a properly initialized ConftestEvaluator for usage
func NewConftestEvaluator(ctx context.Context, policySources []source.PolicySource, namespaces []string) (*ConftestEvaluator, error) {
	c := &ConftestEvaluator{
		Context:       ctx,
		PolicySources: policySources,
		Paths:         ConfigurationPaths{},
		Namespace:     namespaces,
		OutputFormat:  "json",
	}

	dir, err := c.createWorkDir()
	if err != nil {
		return nil, err
	}
	c.WorkDir = dir

	err = c.addPolicyPaths()
	if err != nil {
		return nil, err
	}

	err = c.addDataPath()
	if err != nil {
		return nil, err
	}

	c.TestRunner = runner.TestRunner{
		Data:      c.Paths.DataPaths,
		Policy:    c.Paths.PolicyPaths,
		Namespace: c.Namespace,
		NoFail:    true,
		Output:    c.OutputFormat,
	}

	return c, nil
}

// addDataPath adds the appropriate data path to the ConfigurationPaths DataPaths field array.
func (c *ConftestEvaluator) addDataPath() error {
	// Todo: Read from epc.Spec and right the nonblocking to this file.
	dataDir := filepath.Join(c.WorkDir, "data")
	exists, err := afero.DirExists(utils.AppFS, dataDir)
	if err != nil {
		return err
	}
	if !exists {
		_ = utils.AppFS.MkdirAll(dataDir, 0755)
		err = afero.WriteFile(utils.AppFS, filepath.Join(c.WorkDir, "data/data.json"), []byte("{\"config\":{}}\n"), 0777)
		if err != nil {
			return err
		}
	}
	c.Paths.DataPaths = append(c.Paths.DataPaths, dataDir)

	return nil
}

// addPolicyPaths adds the appropriate policy path to the ConfigurationPaths PolicyPaths field array
func (c *ConftestEvaluator) addPolicyPaths() error {
	for _, policy := range c.PolicySources {
		err := policy.GetPolicies(c.WorkDir)
		if err != nil {
			return err
		}
		policyDir := policy.GetPolicyDir()
		policyPath := filepath.Join(c.WorkDir, policyDir)
		c.Paths.PolicyPaths = append(c.Paths.PolicyPaths, policyPath)
	}
	return nil
}

// createWorkDir creates the working directory in tmp
func (c *ConftestEvaluator) createWorkDir() (string, error) {
	return CreateWorkDir(utils.AppFS, afero.GetTempDir(utils.AppFS, ""), "ec-work-")
}
