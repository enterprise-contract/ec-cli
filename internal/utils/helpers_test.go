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

package utils

import (
	"reflect"
	"testing"
)

var testJSONPipelineData = `{
    "apiVersion": "tekton.dev/v1beta1",
    "kind": "Pipeline",
    "metadata": {
        "name": "run-component-build"
    }
}
`

var testYAMLPipelineData = `apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: run-component-build
`

var testYamlConvertedToJSON = `{"apiVersion":"tekton.dev/v1beta1","kind":"Pipeline","metadata":{"name":"run-component-build"}}`

var testJSONMissingPrefix = `"apiVersion": "tekton.dev/v1beta1",
    "kind": "Pipeline",
    "metadata": {
        "name": "run-component-build"
    }
}
`

var testHasPrefixData = `[
  this is a test 
]`

func TestToJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:    "Returns JSON unchanged",
			args:    args{data: []byte(testJSONPipelineData)},
			want:    []byte(testJSONPipelineData),
			wantErr: false,
		},
		{
			name:    "Converts YAML to JSON",
			args:    args{data: []byte(testYAMLPipelineData)},
			want:    []byte(testYamlConvertedToJSON),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToJSON(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToJSON() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hasJSONPrefix(t *testing.T) {
	type args struct {
		buf []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Returns true when []byte begins with JSON prefix",
			args: args{buf: []byte(testJSONPipelineData)},
			want: true,
		},
		{
			name: "Returns false when []byte begins with JSON prefix",
			args: args{buf: []byte(testJSONMissingPrefix)},
			want: false,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasJSONPrefix(tt.args.buf); got != tt.want {
				t.Errorf("hasJSONPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hasPrefix(t *testing.T) {
	type args struct {
		buf    []byte
		prefix []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Returns true if []byte begins with the specified prefix",
			args: args{
				buf:    []byte(testHasPrefixData),
				prefix: []byte("["),
			},
			want: true,
		},
		{
			name: "Returns false if []byte doesn't begins with the specified prefix",
			args: args{
				buf:    []byte(testHasPrefixData),
				prefix: []byte("{"),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasPrefix(tt.args.buf, tt.args.prefix); got != tt.want {
				t.Errorf("hasPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}
