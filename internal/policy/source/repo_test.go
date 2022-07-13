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

package source

import (
	"context"
	"testing"

	"github.com/go-git/go-git/v5"
)

func checkoutRepoMock(_ context.Context, _ string, _ bool, _ *git.CloneOptions) (*git.Repository, error) {
	return &git.Repository{}, nil
}

func TestPolicyRepo_getPolicies(t *testing.T) {
	type fields struct {
		PolicyDir string
		RepoURL   string
		RepoRef   string
	}
	type args struct {
		dest string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Gets Policies",
			fields: fields{
				PolicyDir: "policy",
				RepoURL:   "https://example.com/user/foo.git",
				RepoRef:   "main",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			CheckoutRepo = checkoutRepoMock
			p := &PolicyRepo{
				PolicyDir: tt.fields.PolicyDir,
				RepoURL:   tt.fields.RepoURL,
				RepoRef:   tt.fields.RepoRef,
			}
			if err := p.GetPolicies(context.TODO(), tt.args.dest); (err != nil) != tt.wantErr {
				t.Errorf("GetPolicies() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPolicyRepo_getPolicyDir(t *testing.T) {
	type fields struct {
		PolicyDir string
		RepoURL   string
		RepoRef   string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Returns Policy Directory",
			fields: fields{
				PolicyDir: "policies",
				RepoURL:   "https://example.com/user/foo.git",
				RepoRef:   "mail",
			},
			want: "policies",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PolicyRepo{
				PolicyDir: tt.fields.PolicyDir,
				RepoURL:   tt.fields.RepoURL,
				RepoRef:   tt.fields.RepoRef,
			}
			if got := p.GetPolicyDir(); got != tt.want {
				t.Errorf("GetPolicyDir() = %v, want %v", got, tt.want)
			}
		})
	}
}
