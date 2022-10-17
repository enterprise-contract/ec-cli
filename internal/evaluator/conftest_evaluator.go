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
	"encoding/json"
	"path/filepath"
	"time"

	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/open-policy-agent/conftest/output"
	"github.com/open-policy-agent/conftest/runner"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/hacbs-contract/ec-cli/internal/downloader"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
	"github.com/hacbs-contract/ec-cli/internal/utils"
)

type contextKey string

const clientContextKey contextKey = "ec.evaluator.client"

type testRunner interface {
	Run(context.Context, []string) ([]output.CheckResult, error)
}

func withClient(ctx context.Context, clnt testRunner) context.Context {
	return context.WithValue(ctx, clientContextKey, clnt)
}

func newClient(ctx context.Context, c conftestEvaluator) testRunner {
	tr, ok := ctx.Value(clientContextKey).(testRunner)
	if ok && tr != nil {
		return tr
	}

	return &runner.TestRunner{
		Data: c.paths.DataPaths,
		// c.paths.PolicyPaths is not actually needed any more since all
		// policies are are now placed under "policy" in the workdir.
		// Todo: Refactor and remove it.
		// Policy:    c.paths.PolicyPaths,
		Policy:    []string{filepath.Join(c.workDir, downloader.PolicyDir)},
		Namespace: []string{c.namespace},
		NoFail:    true,
		Output:    c.outputFormat,
	}
}

// ConftestEvaluator represents a structure which can be used to evaluate targets
type conftestEvaluator struct {
	policySources []source.PolicySource
	paths         ConfigurationPaths
	testRunner    testRunner
	namespace     string
	outputFormat  string
	workDir       string
}

//ConfigurationPaths is a structs containing necessary paths for an Evaluator struct
type ConfigurationPaths struct {
	PolicyPaths []string
	DataPaths   []string
}

// NewConftestEvaluator returns initialized conftestEvaluator implementing
// Evaluator interface
func NewConftestEvaluator(ctx context.Context, policySources []source.PolicySource, namespace string, ecpSpec *ecc.EnterpriseContractPolicySpec) (Evaluator, error) {
	c := conftestEvaluator{
		policySources: policySources,
		paths:         ConfigurationPaths{},
		namespace:     namespace,
		outputFormat:  "json",
	}

	dir, err := utils.CreateWorkDir()
	if err != nil {
		log.Debug("Failed to create work dir!")
		return nil, err
	}
	c.workDir = dir
	log.Debugf("Created work dir %s", dir)

	err = c.addPolicyPaths(ctx)
	if err != nil {
		log.Debug("Failed to add policy paths!")
		return nil, err
	}
	log.Debug("Added policy paths")

	err = c.addDataPath(ecpSpec)
	if err != nil {
		log.Debug("Failed to add add data path!")
		return nil, err
	}
	log.Debug("Added data path")

	c.testRunner = newClient(ctx, c)

	log.Debug("Conftest test runner created")
	return c, nil
}

func (c conftestEvaluator) Evaluate(ctx context.Context, inputs []string) ([]output.CheckResult, error) {
	log.Debugf("c.testRunner: %#v", c.testRunner)
	log.Debugf("inputs: %#v", inputs)
	results, err := c.testRunner.Run(ctx, inputs)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for i, result := range results {
		failures := []output.Result{}
		for _, failure := range result.Failures {
			if !isResultEffective(failure, now) {
				// TODO: Instead of moving to warnings, create new attribute: "futureViolations"
				result.Warnings = append(result.Warnings, failure)
			} else {
				failures = append(failures, failure)
			}
		}
		result.Failures = failures
		results[i] = result
	}

	return results, nil
}

// addDataPath adds the appropriate data path to the ConfigurationPaths DataPaths field array.
func (c *conftestEvaluator) addDataPath(spec *ecc.EnterpriseContractPolicySpec) error {
	dataDir := filepath.Join(c.workDir, "data")
	dataFilePath := filepath.Join(dataDir, "data.json")
	exists, err := afero.DirExists(utils.AppFS, dataDir)
	if err != nil {
		return err
	}
	if !exists {
		log.Debugf("Data dir '%s' does not exist, will create.", dataDir)
		_ = utils.AppFS.MkdirAll(dataDir, 0755)
	}

	var config = map[string]interface{}{
		"config": map[string]interface{}{},
	}

	if spec != nil {
		if spec.Exceptions != nil {
			log.Debug("Non-blocking exceptions found. These will be written to file", dataDir)
			config["config"] = map[string]interface{}{
				"policy": map[string]interface{}{
					"non_blocking_checks": spec.Exceptions.NonBlocking,
					"exclude_rules":       spec.Exceptions.NonBlocking,
				},
			}
		}
	}

	jsonData, marshalErr := json.MarshalIndent(config, "", "    ")
	if marshalErr != nil {
		return err
	}
	// Check to see if the data.json file exists
	exists, err = afero.Exists(utils.AppFS, dataFilePath)
	if err != nil {
		return err
	}
	// if so, remove it
	if exists {
		err = utils.AppFS.Remove(dataFilePath)
		if err != nil {
			return err
		}
	}
	// write our jsonData content to the data.json file in the data directory under the workDir
	log.Debugf("Writing config data to %s: %#v", dataFilePath, string(jsonData))
	err = afero.WriteFile(utils.AppFS, dataFilePath, jsonData, 0777)
	if err != nil {
		return err
	}

	c.paths.DataPaths = append(c.paths.DataPaths, dataDir)

	return nil
}

// addPolicyPaths adds the appropriate policy path to the ConfigurationPaths PolicyPaths field array
func (c *conftestEvaluator) addPolicyPaths(ctx context.Context) error {
	for _, policy := range c.policySources {
		log.Debugf("Policy source: %#v", policy)
		err := policy.GetPolicies(ctx, c.workDir, false)
		if err != nil {
			return err
		}
	}
	return nil
}

const (
	effectiveOnKey    = "effective_on"
	effectiveOnFormat = "2006-01-02T15:04:05Z"
)

// isResultEffective returns whether or not the given result's effective date is before now.
// Failure to determine the effective date is reported as the result being effective.
func isResultEffective(failure output.Result, now time.Time) bool {
	raw, ok := failure.Metadata[effectiveOnKey]
	if !ok {
		return true
	}
	str, ok := raw.(string)
	if !ok {
		log.Warnf("Ignoring non-string %q value %#v", effectiveOnKey, raw)
		return true
	}
	effectiveOn, err := time.Parse(effectiveOnFormat, str)
	if err != nil {
		log.Warnf("Invalid %q value %q", effectiveOnKey, failure.Metadata)
		return true
	}
	return effectiveOn.Before(now)
}
