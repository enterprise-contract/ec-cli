// Copyright The Conforma Contributors
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
	"fmt"
	"sync/atomic"

	"sigs.k8s.io/kind/pkg/log"

	"github.com/conforma/cli/acceptance/testenv"
)

type loggerKeyType int

const loggerKey loggerKeyType = 0

var counter atomic.Uint32

type DelegateLogger interface {
	Log(args ...any)
	Logf(format string, args ...any)
}

type Logger interface {
	DelegateLogger
	Enabled() bool
	Error(message string)
	Errorf(format string, args ...any)
	Info(message string)
	Infof(format string, args ...any)
	Name(name string)
	Printf(format string, v ...any)
	V(level log.Level) log.InfoLogger
	Warn(message string)
	Warnf(format string, args ...any)
}

type logger struct {
	id   uint32
	name string
	t    DelegateLogger
}

// Log logs given arguments
func (l logger) Log(args ...any) {
	l.t.Logf("(%010d: %s) %s", l.id, l.name, fmt.Sprint(args...))
}

// Logf logs using given format and specified arguments
func (l logger) Logf(format string, args ...any) {
	l.t.Logf("(%010d: %s) "+format, append([]any{l.id, l.name}, args...)...)
}

// Printf logs using given format and specified arguments
func (l logger) Printf(format string, args ...any) {
	l.t.Logf("(%010d: %s) "+format, append([]any{l.id, l.name}, args...)...)
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

func (l *logger) Name(name string) {
	l.name = name
}

// LoggerFor returns the logger for the provided Context, it is
// expected that a *testing.T instance is stored in the Context
// under the TestingKey key
func LoggerFor(ctx context.Context) (Logger, context.Context) {
	if logger, ok := ctx.Value(loggerKey).(Logger); ok {
		return logger, ctx
	}

	delegate, ok := ctx.Value(testenv.TestingT).(DelegateLogger)
	if !ok {
		panic("No testing.T found in context")
	}

	logger := logger{
		t:    delegate,
		id:   counter.Add(1),
		name: "*",
	}

	return &logger, context.WithValue(ctx, loggerKey, &logger)
}
