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

package error

import (
	"fmt"
	"runtime"
)

type Error interface {
	error
	CausedBy(error) Error
	CausedByF(format string, args ...any) Error
	Alike(other error) bool
}

type ecError struct {
	code       string
	message    string
	cause      string
	exitStatus int
	file       string
	line       int
}

const (
	SuccessExitStatus = iota
	ErrorExitStatus
	PolicyExitStatus
)

func NewError(code, message string, exitStatus int) Error {
	file, line := callerInfo()
	return &ecError{
		code:       code,
		message:    message,
		exitStatus: exitStatus,
		file:       file,
		line:       line,
	}
}

func (e ecError) CausedBy(err error) Error {
	if err == nil {
		return nil
	}

	file, line := callerInfo()

	return &ecError{
		code:       e.code,
		message:    e.message,
		cause:      err.Error(),
		exitStatus: e.exitStatus,
		file:       file,
		line:       line,
	}
}

func (e ecError) CausedByF(format string, args ...any) Error {
	file, line := callerInfo()

	return &ecError{
		code:       e.code,
		message:    e.message,
		cause:      fmt.Sprintf(format, args...),
		exitStatus: e.exitStatus,
		file:       file,
		line:       line,
	}
}

func (e ecError) Error() string {
	if e.cause == "" {
		return fmt.Sprintf("%s: %s, at %s:%d", e.code, e.message, e.file, e.line)
	}
	return fmt.Sprintf("%s: %s, at %s:%d, caused by: %s", e.code, e.message, e.file, e.line, e.cause)
}

// Alike returns true if two ecErros share the same code and cause
func (e ecError) Alike(other error) bool {
	var cmp ecError
	switch another := other.(type) {
	case *ecError:
		cmp = *another
	case ecError:
		cmp = another
	default:
		return false
	}

	return cmp.code == e.code && cmp.cause == e.cause
}

func callerInfo() (file string, line int) {
	var ok bool
	if _, file, line, ok = runtime.Caller(2); !ok {
		file = "unknown"
		line = 0
	}

	return
}
