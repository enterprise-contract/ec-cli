package pipeline

import (
	"context"
	"github.com/hacbs-contract/ec-cli/cmd/internal/utils"
	"github.com/open-policy-agent/conftest/runner"
	"github.com/spf13/afero"
	"path/filepath"
)

var createWorkDir = afero.TempDir

//Evaluator is a struct containing the required elements to evaluate an associated EvaluationTarget
//using associated PolicySource objects.
type Evaluator struct {
	Context       context.Context
	Target        EvaluationTarget
	PolicySources []PolicySource
	Paths         ConfigurationPaths
	TestRunner    runner.TestRunner
	Namespace     []string
	OutputFormat  string
	workDir       string
}

//ConfigurationPaths is a structs containing necessary paths for an Evaluator struct
type ConfigurationPaths struct {
	PolicyPaths []string
	DataPaths   []string
}

func (e *Evaluator) addDataPath() error {
	dataDir := filepath.Join(e.workDir, "data")
	exists, err := afero.DirExists(utils.AppFS, dataDir)
	if err != nil {
		return err
	}
	if !exists {
		_ = utils.AppFS.MkdirAll(dataDir, 0755)
		err = afero.WriteFile(utils.AppFS, filepath.Join( e.workDir, "data/data.json"), []byte("{\"config\":{}}\n"), 0777)
		if err != nil {
			return err
		}
	}
	e.Paths.DataPaths = append(e.Paths.DataPaths, dataDir)
	return nil
}
func (e *Evaluator) addPolicyPaths() error {
	for i := range e.PolicySources {
		err := e.PolicySources[i].getPolicies(e.workDir)
		if err != nil {
			return err
		}
		policyDir := e.PolicySources[i].getPolicyDir()
		policyPath := filepath.Join(e.workDir, policyDir)
		e.Paths.PolicyPaths = append(e.Paths.PolicyPaths, policyPath)
	}
	return nil
}
func (e *Evaluator) createWorkDir() (string, error) {
	return createWorkDir(utils.AppFS, afero.GetTempDir(utils.AppFS, ""), "ec-work-")
}
