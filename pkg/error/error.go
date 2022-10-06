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
)

type Error interface {
	error
	CausedBy(error) Error
}

type ecError struct {
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

func NewError(code, message string, exitStatus int) Error {
	return &ecError{
		code:       code,
		message:    message,
		exitStatus: exitStatus,
	}
}

func (e ecError) CausedBy(err error) Error {
	if err == nil {
		return nil
	}

	return &ecError{
		code:       e.code,
		message:    e.message,
		cause:      err.Error(),
		exitStatus: e.exitStatus,
	}
}

func (e ecError) Error() string {
	return fmt.Sprintf("%s: %s, caused by: %s", e.code, e.message, e.cause)
}
