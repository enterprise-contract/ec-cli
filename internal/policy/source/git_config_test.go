// Copyright The Conforma Contributors
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

package source

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSourceIsFile(t *testing.T) {
	tests := []struct {
		src  string
		want bool
	}{
		{src: "", want: false},
		{src: "foo", want: false},
		{src: "https://foo.bar/asdf", want: false},
		{src: "git::https://foo.bar/asdf", want: false},
		{src: "git::github.com/foo/bar", want: false},
		{src: "https://raw.githubusercontent.com/foo/bar", want: false},
		{src: "gitlab.com/foo/bar", want: false},
		{src: "/file/path/to/foo/policy.yaml", want: true},
		{src: "../../file/path/to/foo/policy.yaml", want: true},
		{src: "github.com/foo/bar", want: false},
		{src: "s3::github.com/foo/bar", want: false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, SourceIsFile(tt.src), "SourceIsFile(%s) = %v, want %v", tt.src, SourceIsFile(tt.src), tt.want)
	}
}

func TestSourceIsGit(t *testing.T) {
	tests := []struct {
		src  string
		want bool
	}{
		{src: "", want: false},
		{src: "foo", want: false},
		{src: "foo.bar/asdf", want: false},
		{src: "git::https://foo.bar/asdf", want: true},
		{src: "git::github.com/foo/bar", want: true},
		{src: "https://raw.githubusercontent.com/foo/bar", want: false},
		{src: "gitlab.com/foo/bar", want: true},
		{src: "github.com/foo/bar", want: true},
		{src: "s3::github.com/foo/bar", want: false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, SourceIsGit(tt.src), "SourceIsGit(%s) = %v, want %v", tt.src, SourceIsGit(tt.src), tt.want)
	}
}

func TestSourceIsHttp(t *testing.T) {
	tests := []struct {
		src  string
		want bool
	}{
		{src: "", want: false},
		{src: "foo", want: false},
		{src: "foo.bar/asdf", want: false},
		{src: "git::https://foo.bar/asdf", want: false},
		{src: "git::github.com/foo/bar", want: false},
		{src: "https://raw.githubusercontent.com/foo/bar", want: true},
		{src: "raw.githubusercontent.com/foo/bar", want: false},
		{src: "gitlab.com/foo/bar", want: false},
		{src: "github.com/foo/bar", want: false},
		{src: "s3::github.com/foo/bar", want: false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, SourceIsHttp(tt.src), "SourceIsHttp(%s) = %v, want %v", tt.src, SourceIsHttp(tt.src), tt.want)
	}
}
