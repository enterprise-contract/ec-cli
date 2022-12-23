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

// Package log forwards logs to testing.T.Log* methods
package log

import (
	"context"
	"testing"

	"github.com/hacbs-contract/ec-cli/acceptance/testenv"
)

type Logger interface {
	Log(args ...interface{})
	Logf(format string, args ...interface{})
	Printf(format string, v ...interface{})
}

type logger struct {
	t *testing.T
}

// Log logs given arguments
func (l logger) Log(args ...interface{}) {
	l.t.Log(args...)
}

// Logf logs using given format and specified arguments
func (l logger) Logf(format string, args ...interface{}) {
	l.t.Logf(format, args...)
}

// Printf logs using given format and specified arguments
func (l logger) Printf(format string, args ...interface{}) {
	l.Logf(format, args...)
}

// LoggerFor returns the logger for the provided Context, it is
// expected that a *testing.T instance is stored in the Context
// under the TestingKey key
func LoggerFor(ctx context.Context) Logger {
	return logger{testenv.Testing(ctx)}
}
