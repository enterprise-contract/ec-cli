package pipeline

import (
	"context"

	"github.com/hacbs-contract/ec-cli/cmd/internal/policy"
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
