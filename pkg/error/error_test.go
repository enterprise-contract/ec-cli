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

package error

import (
	"errors"
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
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
		want   *ecError
	}{
		{
			name: "returns underlying error message",
			fields: fields{
				code:       "GE001",
				message:    "General error",
				exitStatus: 0,
			},
			args: args{err: errors.New("A mistake")},
			want: &ecError{
				code:       "GE001",
				message:    "General error",
				cause:      "A mistake",
				exitStatus: 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ecError{
				code:       tt.fields.code,
				message:    tt.fields.message,
				cause:      tt.fields.cause,
				exitStatus: tt.fields.exitStatus,
			}
			_, file, line, ok := runtime.Caller(0)
			assert.True(t, ok)
			tt.want.file = file
			tt.want.line = line + 4
			assert.Equal(t, tt.want, e.CausedBy(tt.args.err))
		})
	}
}

func TestError_Error(t *testing.T) {
	type fields struct {
		code       string
		message    string
		cause      string
		exitStatus int
		file       string
		line       int
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
				file:       "file.go",
				line:       10,
			},
			want: "GE001: Something is wrong, at file.go:10, caused by: error detected",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := ecError{
				code:       tt.fields.code,
				message:    tt.fields.message,
				cause:      tt.fields.cause,
				exitStatus: tt.fields.exitStatus,
				file:       tt.fields.file,
				line:       tt.fields.line,
			}
			assert.Equal(t, tt.want, e.Error())
		})
	}
}

func TestNilCauses(t *testing.T) {
	assert.Nil(t, ecError{}.CausedBy(nil))
}

func TestNoCausedBy(t *testing.T) {
	_, file, line, ok := runtime.Caller(0)
	assert.True(t, ok)
	e := NewError("CO001", "message", ErrorExitStatus)
	assert.Equal(t, fmt.Sprintf("CO001: message, at %s:%d", file, line+2), e.Error())
}

func TestWithCausedBy(t *testing.T) {
	_, file, line, ok := runtime.Caller(0)
	assert.True(t, ok)
	e := NewError("CO001", "message", ErrorExitStatus).CausedBy(errors.New("boom"))
	assert.Equal(t, fmt.Sprintf("CO001: message, at %s:%d, caused by: boom", file, line+2), e.Error())
}

func TestWithCausedByF(t *testing.T) {
	_, file, line, ok := runtime.Caller(0)
	assert.True(t, ok)
	e := NewError("CO001", "message", ErrorExitStatus).CausedByF("error: %s %d", "boom", 4)
	assert.Equal(t, fmt.Sprintf("CO001: message, at %s:%d, caused by: error: boom 4", file, line+2), e.Error())
}
