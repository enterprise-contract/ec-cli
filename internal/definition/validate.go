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
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/hacbs-contract/ec-cli/internal/evaluation_target/definition"
	"github.com/hacbs-contract/ec-cli/internal/output"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
	"github.com/hacbs-contract/ec-cli/internal/utils"
)

var def_file = definition.NewDefinition
var pathExists = afero.Exists

// ValidatePipeline calls NewPipelineEvaluator to obtain an PipelineEvaluator. It then executes the associated TestRunner
// which tests the associated pipeline file(s) against the associated policies, and displays the output.
func ValidateDefinition(ctx context.Context, fpath string, sources []source.PolicySource, namespace []string) (*output.Output, error) {
	defFiles, err := fileDetection(ctx, fpath)
	if err != nil {
		return nil, err
	}
	p, err := def_file(ctx, defFiles, sources, namespace)
	if err != nil {
		log.Debug("Failed to create pipeline definition file!")
		return nil, err
	}

	results, err := p.Evaluator.Evaluate(ctx, defFiles)
	if err != nil {
		log.Debug("Problem running conftest policy check!")
		return nil, err
	}
	log.Debug("Conftest policy check complete")
	return &output.Output{PolicyCheck: results}, nil
}

// detect if a file or directory was passed. if a directory, gather all files in it
func fileDetection(ctx context.Context, fpath string) ([]string, error) {
	fs := utils.FS(ctx)
	exists, err := pathExists(fs, fpath)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("fpath '%s' does not exist", fpath)
	}

	var defFiles []string
	file, err := os.Open(fpath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// This returns an *os.FileInfo type
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// IsDir is short for fileInfo.Mode().IsDir()
	if fileInfo.IsDir() {
		files, err := os.ReadDir(fpath)
		if err != nil {
			log.Fatal(err)
		}

		for _, f := range files {
			defFiles = append(defFiles, fmt.Sprintf("%s/%s", fpath, f.Name()))
		}
	} else {
		defFiles = append(defFiles, fpath)

	}

	return defFiles, nil
}
