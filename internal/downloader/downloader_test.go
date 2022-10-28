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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockDownloader struct {
	mock.Mock
}

func (m *mockDownloader) Download(ctx context.Context, dest string, sourceUrls []string) error {
	args := m.Called(ctx, dest, sourceUrls)

	return args.Error(0)
}

func TestDownloader_Download(t *testing.T) {
	tests := []struct {
		name   string
		dest   string
		source string
		err    error
	}{
		{
			name:   "Downloads",
			dest:   "dir",
			source: "example.com/repo.git",
		},
		{
			name:   "Fails to download",
			dest:   "dir",
			source: "example.com/repo.git",
			err:    errors.New("expected"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := mockDownloader{}
			ctx := WithDownloadImpl(context.TODO(), &d)
			d.On("Download", ctx, tt.dest, []string{tt.source}).Return(tt.err)

			err := Download(ctx, tt.dest, tt.source, false)
			if tt.err == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.err.Error())
			}

			mock.AssertExpectationsForObjects(t, &d)
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
