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

package downloader

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var mockCalled bool
var mockArgs string

func mockCtdlDownload(_ context.Context, dst string, urls []string) error {
	mockCalled = true
	mockArgs = fmt.Sprintf("%v, %v", dst, urls)
	return nil
}

func mockUniqueDir(_ string) string {
	return "123456"
}

func TestDownloader_Download(t *testing.T) {
	CtdlDownload = mockCtdlDownload
	UniqueDir = mockUniqueDir

	tests := []struct {
		name      string
		downloadF func(context.Context, string, string, bool) error
		dest      string
		source    string
		wantArgs  string
	}{
		{
			name:      "Download",
			downloadF: Download,
			dest:      "dir",
			source:    "example.com/repo.git",
			wantArgs:  "dir, [example.com/repo.git]",
		},
		{
			name:      "DownloadPolicy",
			downloadF: DownloadPolicy,
			dest:      "dir",
			source:    "example.com/repo//somedir",
			wantArgs:  "dir/policy/123456, [example.com/repo//somedir]",
		},
		{
			name:      "DownloadData",
			downloadF: DownloadData,
			dest:      "dir",
			source:    "example.com/repo//somedir",
			wantArgs:  "dir/data/123456, [example.com/repo//somedir]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.downloadF(context.TODO(), tt.dest, tt.source, true)

			assert.Nil(t, err, "Unexpected error")
			assert.True(t, mockCalled, "Download not called")
			assert.Equal(t, mockArgs, tt.wantArgs, "Download called with unexpected args")
		})
	}

}

func TestDownloader_ProbablyGoGetterFormat(t *testing.T) {
	falseUrls := []string{
		"https://github.com/hacbs-contract/ec-policies",
		"github.com/hacbs-contract/ec-policies",
		"github.com/hacbs-contract/ec-policies.git",
		"https://github.com/hacbs-contract/ec-policies/policy",
	}
	for _, u := range falseUrls {
		t.Run(u, func(t *testing.T) {
			assert.False(t, ProbablyGoGetterFormat(u))
		})
	}

	trueUrls := []string{
		"github.com/hacbs-contract/ec-policies//policy",
		"github.com/hacbs-contract/ec-policies?ref=main",
		"git::github.com/hacbs-contract/ec-policies",
	}
	for _, u := range trueUrls {
		t.Run(u, func(t *testing.T) {
			assert.True(t, ProbablyGoGetterFormat(u))
		})
	}
}

func TestDownloader_ProbablyDataSource(t *testing.T) {
	falseUrls := []string{
		"github.com/hacbs-contract/ec-policies//policy",
		"github.com/hacbs-contract/ec-policies?ref=devel",
	}
	for _, u := range falseUrls {
		t.Run(u, func(t *testing.T) {
			assert.False(t, ProbablyDataSource(u))
		})
	}

	trueUrls := []string{
		"github.com/hacbs-contract/ec-policies//data",
		"github.com/some/repo//other/data?ref=devel",
	}
	for _, u := range trueUrls {
		t.Run(u, func(t *testing.T) {
			assert.True(t, ProbablyDataSource(u))
		})
	}
}

func TestDownloader_GetterGitUrl(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantArgs string
	}{
		{
			name:     "Download",
			args:     []string{"foo", "bar", "baz"},
			wantArgs: "git::foo//bar?ref=baz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantArgs, GetterGitUrl(tt.args[0], tt.args[1], tt.args[2]))
		})
	}
}
