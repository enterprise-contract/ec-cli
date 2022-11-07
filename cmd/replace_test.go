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

//go:build unit

package cmd

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/hacbs-contract/ec-cli/internal/replacer"
)

type mockReplacer struct {
	mock.Mock
}

func (m *mockReplacer) replace(ctx context.Context, images []string, source string, overwrite bool, opts *replacer.CatalogOptions) ([]byte, error) {
	args := m.Called(ctx, images, source, overwrite, opts)

	return args.Get(0).([]byte), args.Error(1)
}

func TestReplaceCmd(t *testing.T) {
	cases := []struct {
		name                  string
		source                string
		overwrite             bool
		outputFile            string
		catalogName           string
		catalogRepositoryBase string
		catalogHubAPI         string
		images                []string
		expectedOutput        []byte
		expectedStderr        string
		err                   error
	}{
		{
			name:           "output to out",
			source:         "https://git.example.com/org/repo",
			images:         []string{"registry.io/a", "registry.io/b", "registry.io/c"},
			expectedOutput: []byte("expected bytes"),
		},
		{
			name:           "fails in replace",
			source:         "something",
			expectedStderr: "Error: expected\n",
			err:            errors.New("expected"),
		},
		{
			name:           "outputs to file",
			source:         "something",
			outputFile:     "out.txt",
			expectedOutput: []byte("expected bytes"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := mockReplacer{}

			replace := replaceCmd(m.replace)

			fs := afero.NewMemMapFs()
			ctx := withFs(context.TODO(), fs)
			replace.SetContext(ctx)

			replace.SilenceUsage = true

			var stdout bytes.Buffer
			replace.SetOut(&stdout)

			var stderr bytes.Buffer
			replace.SetErr(&stderr)

			args := []string{
				"--source",
				c.source,
			}

			if c.overwrite {
				args = append(args, "--overwrite")
			}

			if c.outputFile != "" {
				args = append(args, "--output", c.outputFile)
			}

			if c.catalogName == "" {
				c.catalogName = defaultCatalogName
			} else {
				args = append(args, "--catalog-name", c.catalogName)
			}

			if c.catalogRepositoryBase == "" {
				c.catalogRepositoryBase = defaultRepositoryBase
			} else {
				args = append(args, "--catalog-repo-base", c.catalogRepositoryBase)
			}

			if c.catalogHubAPI == "" {
				c.catalogHubAPI = defaultHubAPIURL
			} else {
				args = append(args, "--catalog-hub-api", c.catalogHubAPI)
			}

			if c.images == nil {
				c.images = []string{}
			} else {
				args = append(args, c.images...)
			}

			replace.SetArgs(args)

			m.On("replace", ctx, c.images, c.source, c.overwrite, &replacer.CatalogOptions{
				CatalogName: c.catalogName,
				RepoBase:    c.catalogRepositoryBase,
				HubAPIURL:   c.catalogHubAPI,
			}).Return(c.expectedOutput, c.err)

			err := replace.Execute()

			if c.outputFile == "" {
				assert.Equal(t, string(c.expectedOutput), stdout.String(), "stdout differs")
			} else {
				bytes, err := afero.ReadFile(fs, c.outputFile)
				assert.NoError(t, err)
				assert.Equal(t, c.expectedOutput, bytes)
			}
			assert.Equal(t, string(c.expectedStderr), stderr.String(), "stderr differs")

			if c.err == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, c.err.Error())
			}
		})
	}
}
