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

//go:build unit

package inspect

import (
	"bytes"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/net/context"

	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

type mockDownloader struct {
	mock.Mock
}

func (m *mockDownloader) Download(_ context.Context, dest string, sourceUrl string, showMsg bool) error {
	args := m.Called(dest, sourceUrl, showMsg)

	return args.Error(0)
}

func TestFetchSourcesFromPolicy(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	downloader := mockDownloader{}
	ctx = context.WithValue(ctx, source.DownloaderFuncKey, &downloader)

	createDir := func(args mock.Arguments) {
		dir := args.String(0)

		if err := fs.MkdirAll(dir, 0755); err != nil {
			panic(err)
		}
	}

	downloader.On("Download", mock.Anything, "one", false).Return(nil).Run(createDir)
	downloader.On("Download", mock.Anything, "two", false).Return(nil).Run(createDir)
	downloader.On("Download", mock.Anything, "three", false).Return(nil).Run(createDir)

	cmd := inspectPolicyCmd()
	cmd.SetContext(ctx)
	buffy := bytes.Buffer{}
	cmd.SetOut(&buffy)

	cmd.SetArgs([]string{
		"--policy",
		`{"sources":[{"policy":["one","two"]},{"policy":["three"]}]}`,
	})

	err := cmd.Execute()
	assert.NoError(t, err)

	assert.Equal(t, "[one,two,three]", cmd.Flag("source").Value.String())
	assert.Equal(t, "# Source: one\n\n# Source: three\n\n# Source: two\n\n", buffy.String())
}

func TestFetchSources(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	downloader := mockDownloader{}
	ctx = context.WithValue(ctx, source.DownloaderFuncKey, &downloader)

	createDir := func(args mock.Arguments) {
		dir := args.String(0)

		if err := fs.MkdirAll(dir, 0755); err != nil {
			panic(err)
		}
	}

	downloader.On("Download", mock.Anything, "one", false).Return(nil).Run(createDir)
	downloader.On("Download", mock.Anything, "two", false).Return(nil).Run(createDir)
	downloader.On("Download", mock.Anything, "three", false).Return(nil).Run(createDir)

	cmd := inspectPolicyCmd()
	cmd.SetContext(ctx)
	buffy := bytes.Buffer{}
	cmd.SetOut(&buffy)

	cmd.SetArgs([]string{
		"--source",
		"one",
		"--source",
		"two",
		"--source",
		"three",
	})

	err := cmd.Execute()
	assert.NoError(t, err)

	assert.Equal(t, "[one,two,three]", cmd.Flag("source").Value.String())
	assert.Equal(t, "# Source: one\n\n# Source: three\n\n# Source: two\n\n", buffy.String())
}

func TestSourcesAndPolicyCantBeBothProvided(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	downloader := mockDownloader{}
	ctx = context.WithValue(ctx, source.DownloaderFuncKey, &downloader)

	createDir := func(args mock.Arguments) {
		dir := args.String(0)

		if err := fs.MkdirAll(dir, 0755); err != nil {
			panic(err)
		}
	}

	downloader.On("Download", mock.Anything, "one", false).Return(nil).Run(createDir)
	downloader.On("Download", mock.Anything, "two", false).Return(nil).Run(createDir)
	downloader.On("Download", mock.Anything, "three", false).Return(nil).Run(createDir)

	cmd := inspectPolicyCmd()
	cmd.SetContext(ctx)
	buffy := bytes.Buffer{}
	cmd.SetOut(&buffy)

	cmd.SetArgs([]string{
		"--source",
		"one",
		"--source",
		"two",
		"--source",
		"three",
		"--policy",
		`{"sources":[{"policy":["one","two"]},{"policy":["three"]}]}`,
	})

	err := cmd.Execute()
	assert.Error(t, err, "if any flags in the group [policy source] are set none of the others can be; [policy source] were all set")

	assert.Contains(t, buffy.String(), "Usage:")
}
