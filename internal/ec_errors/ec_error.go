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

package ec_errors

type Error struct {
	code       string
	message    string
	cause      string
	exitStatus int
}

const (
	SuccessExitStatus = iota
	ErrorExitStatus
	PolicyExitStatus
)

var (
	/*
		Additional errors can be added in a similar way as below
	*/
	GE001 = Error{
		code:       "GE001",
		message:    "General error",
		exitStatus: ErrorExitStatus,
	}
)

func (e Error) CausedBy(err error) *Error {
	return &Error{
		code:       e.code,
		message:    e.message,
		cause:      err.Error(),
		exitStatus: e.exitStatus,
	}
}

func (e Error) Error() string {
	return e.cause
}
