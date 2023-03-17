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
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/hacbs-contract/ec-cli/internal/evaluation_target/definition"
	"github.com/hacbs-contract/ec-cli/internal/output"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
	"github.com/hacbs-contract/ec-cli/internal/utils"
)

var definitionFile = definition.NewDefinition

// ValidatePipeline calls NewPipelineEvaluator to obtain an PipelineEvaluator. It then executes the associated TestRunner
// which tests the associated pipeline file(s) against the associated policies, and displays the output.
func ValidateDefinition(ctx context.Context, fpath string, sources []source.PolicySource, namespace []string) (*output.Output, error) {
	defFiles, err := detectFiles(ctx, fpath)
	if err != nil {
		return nil, err
	}
	p, err := definitionFile(ctx, defFiles, sources, namespace)
	if err != nil {
		log.Debug("Failed to create definition file!")
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
func detectFiles(ctx context.Context, fpath string) ([]string, error) {
	if utils.IsJson(fpath) {
		return definitionFromString(ctx, fpath)
	}

	fs := utils.FS(ctx)
	exists, err := afero.Exists(fs, fpath)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("fpath '%s' does not exist", fpath)
	}

	var defFiles []string
	file, err := fs.Open(fpath)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	dir, err := afero.IsDir(fs, fpath)
	if err != nil {
		return nil, err
	}

	if dir {
		files, err := afero.ReadDir(fs, fpath)
		if err != nil {
			return nil, err
		}

		for _, f := range files {
			defFiles = append(defFiles, filepath.Join(fpath, f.Name()))
		}
	} else {
		defFiles = append(defFiles, fpath)
	}

	return defFiles, nil
}

func definitionFromString(ctx context.Context, data string) ([]string, error) {
	data, err := utils.WriteTempFile(ctx, data, "definition-file-")
	if err != nil {
		return nil, err
	}
	return []string{data}, nil
}
