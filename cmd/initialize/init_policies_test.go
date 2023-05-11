// Copyright 2023 Red Hat, Inc.
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
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"

	"github.com/enterprise-contract/ec-cli/internal/utils"
)

func TestFetchSourcesFromPolicy(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	cmd := initCmd()
	cmd.SetContext(ctx)
	buffy := bytes.Buffer{}
	cmd.SetOut(&buffy)

	cmd.SetArgs([]string{
		"--dest-dir",
		"todo",
	})

	err := cmd.Execute()
	assert.NoError(t, err)

	//TODO: assert.Equal(t, "[one,two,three]", cmd.Flag("source").Value.String())
}
