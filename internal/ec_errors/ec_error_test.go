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

package ec_errors

import (
	"errors"
	"reflect"
	"testing"
)

func TestError_CausedBy(t *testing.T) {
	type fields struct {
		code       string
		message    string
		cause      string
		exitStatus int
	}
	type args struct {
		err error
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Error
	}{
		{
			name: "returns underlying error message",
			fields: fields{
				code:       "GE001",
				message:    "General error",
				exitStatus: 0,
			},
			args: args{err: errors.New("A mistake")},
			want: &Error{
				code:       "GE001",
				message:    "General error",
				cause:      "A mistake",
				exitStatus: 0,
			},
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Error{
				code:       tt.fields.code,
				message:    tt.fields.message,
				cause:      tt.fields.cause,
				exitStatus: tt.fields.exitStatus,
			}
			if got := e.CausedBy(tt.args.err); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CausedBy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestError_Error(t *testing.T) {
	type fields struct {
		code       string
		message    string
		cause      string
		exitStatus int
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Test error function returns wrapped error string",
			fields: fields{
				code:       "GE001",
				message:    "Something is wrong",
				cause:      errors.New("error detected").Error(),
				exitStatus: 1,
			},
			want: "error detected",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := Error{
				code:       tt.fields.code,
				message:    tt.fields.message,
				cause:      tt.fields.cause,
				exitStatus: tt.fields.exitStatus,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("Error() = %v, want %v", got, tt.want)
			}
		})
	}
}
