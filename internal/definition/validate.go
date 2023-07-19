// Copyright Red Hat.
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

	"github.com/enterprise-contract/ec-cli/internal/evaluation_target/definition"
	"github.com/enterprise-contract/ec-cli/internal/output"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

var definitionFile = definition.NewDefinition

// ValidatePipeline calls NewPipelineEvaluator to obtain an PipelineEvaluator. It then executes the associated TestRunner
// which tests the associated pipeline file(s) against the associated policies, and displays the output.
func ValidateDefinition(ctx context.Context, fpath string, sources []source.PolicySource, namespace []string) (*output.Output, error) {
	defFiles, err := detectInput(ctx, fpath)
	if err != nil {
		return nil, err
	}
	p, err := definitionFile(ctx, defFiles, sources, namespace)
	if err != nil {
		log.Debug("Failed to create definition file!")
		return nil, err
	}

	results, _, err := p.Evaluator.Evaluate(ctx, defFiles)
	if err != nil {
		log.Debug("Problem running conftest policy check!")
		return nil, err
	}
	log.Debug("Conftest policy check complete")
	return &output.Output{PolicyCheck: results}, nil
}

// detect if a file or directory was passed. if a directory, gather all files in it
// the order is file lookup, json lookup then yaml
func detectInput(ctx context.Context, fpath string) ([]string, error) {
	if utils.IsJson(fpath) {
		log.Debug("valid JSON found for definition file")
		return definitionFromString(ctx, fpath)
	}
	log.Debug("unable to detect input as JSON")

	// this is narrowed down to map[string]interface{}
	// since a provided filename that does not exist could be considered valid yaml
	if utils.IsYamlMap(fpath) {
		log.Debug("valid YAML map found for definition file")
		return definitionFromString(ctx, fpath)
	}
	log.Debug("unable to detect input as YAML")

	fileExists, err := utils.IsFile(ctx, fpath)
	if err != nil {
		return nil, err
	}

	if fileExists {
		return fileLookup(ctx, fpath)
	}
	log.Debugf("unable to detect a file at path %v", fpath)

	return nil, fmt.Errorf("unable to parse the provided definition file: %v", fpath)
}

// if a single file is provided, return it
// if the file is a directory, return the files inside the directory
func fileLookup(ctx context.Context, path string) ([]string, error) {
	fs := utils.FS(ctx)
	var defFiles []string

	file, err := fs.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	dir, err := afero.IsDir(fs, path)
	if err != nil {
		return nil, err
	}

	if dir {
		files, err := afero.ReadDir(fs, path)
		if err != nil {
			return nil, err
		}
		// a directory was provided, but contained no files
		if len(files) == 0 {
			return nil, fmt.Errorf("the directory %v contained no files", path)
		}

		for _, f := range files {
			defFiles = append(defFiles, filepath.Join(path, f.Name()))
		}
	} else {
		defFiles = append(defFiles, path)
	}

	return defFiles, nil
}

// write the definition file if a json or yaml string is provided
func definitionFromString(ctx context.Context, data string) ([]string, error) {
	data, err := utils.WriteTempFile(ctx, data, "definition-file-")
	if err != nil {
		return nil, err
	}
	return []string{data}, nil
}
