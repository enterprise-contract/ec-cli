// Copyright The Enterprise Contract Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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
	"os"
	"path"

	"github.com/spf13/afero"
)

// not sure what the properties will be yet, so setting the minimum.
type opaEvaluator struct {
	workDir string
	fs      afero.Fs
}

func NewOPAEvaluator() (Evaluator, error) {
	return opaEvaluator{}, nil
}

func (o opaEvaluator) Evaluate(ctx context.Context, target EvaluationTarget) ([]Outcome, Data, error) {
	return []Outcome{}, Data{}, nil
}

func (o opaEvaluator) Destroy() {
	if o.workDir != "" && os.Getenv("EC_DEBUG") == "" {
		_ = o.fs.RemoveAll(o.workDir)
	}
}

func (o opaEvaluator) CapabilitiesPath() string {
	return path.Join(o.workDir, "capabilities.json")
}
