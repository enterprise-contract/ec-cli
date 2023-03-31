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

	"sigs.k8s.io/kind/pkg/log"

	"github.com/enterprise-contract/ec-cli/acceptance/testenv"
)

type Logger interface {
	Log(args ...any)
	Logf(format string, args ...any)
	Printf(format string, v ...any)
	Warn(message string)
	Warnf(format string, args ...any)
	Error(message string)
	Errorf(format string, args ...any)
	V(level log.Level) log.InfoLogger
	Info(message string)
	Infof(format string, args ...any)
	Enabled() bool
}

type logger struct {
	t *testing.T
}

// Log logs given arguments
func (l logger) Log(args ...any) {
	l.t.Log(args...)
}

// Logf logs using given format and specified arguments
func (l logger) Logf(format string, args ...any) {
	l.t.Logf(format, args...)
}

// Printf logs using given format and specified arguments
func (l logger) Printf(format string, args ...any) {
	l.Logf(format, args...)
}

func (l logger) Warn(message string) {
	l.Logf("[WARN ] %s", message)
}

func (l logger) Warnf(format string, args ...any) {
	l.Logf("[WARN ] "+format, args...)
}

func (l logger) Error(message string) {
	l.Logf("[ERROR] %s", message)
}

func (l logger) Errorf(format string, args ...any) {
	l.Logf("[ERROR] "+format, args...)
}

func (l logger) Info(message string) {
	l.Logf("[INFO ] %s", message)
}

func (l logger) Infof(format string, args ...any) {
	l.Logf("[INFO ] "+format, args...)
}

func (l logger) V(_ log.Level) log.InfoLogger {
	return l
}

func (l logger) Enabled() bool {
	return true
}

// LoggerFor returns the logger for the provided Context, it is
// expected that a *testing.T instance is stored in the Context
// under the TestingKey key
func LoggerFor(ctx context.Context) Logger {
	return logger{testenv.Testing(ctx)}
}
