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

package source

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func usingDownloader(ctx context.Context, m *mockDownloader) context.Context {
	return context.WithValue(ctx, DownloaderFuncKey, m)
}

type mockDownloader struct {
	mock.Mock
}

func (m *mockDownloader) Download(_ context.Context, dest string, sourceUrl string, showMsg bool) error {
	args := m.Called(dest, sourceUrl, showMsg)

	return args.Error(0)
}

func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name      string
		sourceUrl string
		dest      string
		err       error
	}{
		{
			name:      "Gets policies",
			sourceUrl: "https://example.com/user/foo.git",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			err:       nil,
		},
		{
			name:      "Gets policies with getter style source url",
			sourceUrl: "git::https://example.com/user/foo.git//subdir?ref=devel",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			err:       nil,
		},
		{
			name:      "Fails fetching the policy",
			sourceUrl: "failure",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			err:       errors.New("expected"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := PolicyUrl{Url: tt.sourceUrl, Kind: "policy"}

			dl := mockDownloader{}
			dl.On("Download", mock.MatchedBy(func(dest string) bool {
				matched, err := regexp.MatchString(tt.dest, dest)
				if err != nil {
					panic(err)
				}

				return matched
			}), tt.sourceUrl, false).Return(tt.err)

			_, err := p.GetPolicy(usingDownloader(context.TODO(), &dl), "/tmp/ec-work-1234", false)
			if tt.err == nil {
				assert.NoError(t, err, "GetPolicies returned an error")
			} else {
				assert.EqualError(t, err, tt.err.Error())
			}

			mock.AssertExpectationsForObjects(t, &dl)
		})
	}
}
