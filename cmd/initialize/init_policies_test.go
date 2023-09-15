// Copyright The Enterprise Contract Contributors
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

package initialize

import (
	"bytes"
	"context"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/enterprise-contract/ec-cli/internal/utils"
)

func TestInitializeNoError(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	cmd := initPoliciesCmd()
	cmd.SetContext(ctx)
	buffy := new(bytes.Buffer)
	cmd.SetOut(buffy)

	cmd.SetArgs([]string{
		"--dest-dir",
		"sample",
	})

	err := cmd.Execute()
	assert.NoError(t, err)
}

func TestInitializeSamplePolicy(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	cmd := initPoliciesCmd()
	cmd.SetContext(ctx)
	buffy := new(bytes.Buffer)
	cmd.SetOut(buffy)

	cmd.SetArgs([]string{
		"--dest-dir",
		"sample",
	})

	err := cmd.Execute()
	assert.NoError(t, err)
	samplePolicy, err := afero.ReadFile(fs, "sample/sample.rego")
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, string(samplePolicy), "Simplest never-failing policy")
}

func TestInitializeStdOut(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	cmd := initPoliciesCmd()
	cmd.SetContext(ctx)
	buffy := bytes.Buffer{}
	cmd.SetOut(&buffy)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buffy.String(), "Simplest never-failing policy")
}
