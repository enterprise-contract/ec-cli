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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var mockDownloadPolicyCalled bool
var mockDownloadDataCalled bool
var mockArgs string

func mockDownloadPolicy(_ context.Context, dest string, sourceUrl string, showMsg bool) error {
	mockDownloadPolicyCalled = true
	mockArgs = fmt.Sprintf("%v, %v, %v", dest, sourceUrl, showMsg)
	return nil
}

func mockDownloadData(_ context.Context, dest string, sourceUrl string, showMsg bool) error {
	mockDownloadDataCalled = true
	mockArgs = fmt.Sprintf("%v, %v, %v", dest, sourceUrl, showMsg)
	return nil
}

func TestPolicyUrl_getPolicies(t *testing.T) {
	type args struct {
		dest string
	}
	tests := []struct {
		name           string
		sourceUrl      string
		args           args
		wantArgs       string
		wantDataSource bool
		wantErr        bool
	}{
		{
			name:      "Gets policies",
			sourceUrl: "https://example.com/user/foo.git",
			args: args{
				dest: "/tmp/ec-work-1234",
			},
			wantArgs:       "/tmp/ec-work-1234, https://example.com/user/foo.git, false",
			wantDataSource: false,
		},
		{
			name:      "Gets policies with getter style source url",
			sourceUrl: "git::https://example.com/user/foo.git//subdir?ref=devel",
			args: args{
				dest: "/tmp/ec-work-1234",
			},
			wantArgs:       "/tmp/ec-work-1234, git::https://example.com/user/foo.git//subdir?ref=devel, false",
			wantDataSource: false,
		},
		{
			// It should guess from the url that the source is data instead of policies
			name:      "Gets data",
			sourceUrl: "https://example.com/user/foo.git//data?ref=devel",
			args: args{
				dest: "/tmp/ec-work-1234",
			},
			wantArgs:       "/tmp/ec-work-1234, https://example.com/user/foo.git//data?ref=devel, false",
			wantDataSource: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DownloadPolicy = mockDownloadPolicy
			DownloadData = mockDownloadData

			r := PolicyUrl(tt.sourceUrl)
			p := &r

			mockDownloadPolicyCalled = false
			mockDownloadDataCalled = false
			mockArgs = ""

			assert.Nil(t, p.GetPolicies(context.TODO(), tt.args.dest, false), "GetPolicies returned an error")

			if tt.wantDataSource {
				assert.False(t, mockDownloadPolicyCalled, "DownloadPolicy called unexpectedly")
				assert.True(t, mockDownloadDataCalled, "DownloadData not called")
				assert.Equal(t, tt.wantArgs, mockArgs, "DownloadData called with unexpected args")
			} else {
				assert.False(t, mockDownloadDataCalled, "DownloadData called unexpectedly")
				assert.True(t, mockDownloadPolicyCalled, "DownloadPolicy not called")
				assert.Equal(t, tt.wantArgs, mockArgs, "DownloadPolicy called with unexpected args")
			}
		})
	}
}
