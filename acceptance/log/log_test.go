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

//go:build unit

// Package log forwards logs to testing.T.Log* methods
package log

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/conforma/cli/acceptance/testenv"
)

type mockDelegateLogger struct {
	mock.Mock
}

func (m *mockDelegateLogger) Log(args ...any) {
	m.Called(args)
}

func (m *mockDelegateLogger) Logf(format string, args ...any) {
	m.Called(format, args)
}

func TestLogger(t *testing.T) {
	dl := mockDelegateLogger{}
	ctx := context.WithValue(context.Background(), testenv.TestingT, &dl)

	loggerA, ctx := LoggerFor(ctx)
	loggerA.Name("A")

	assert.Equal(t, loggerA, ctx.Value(loggerKey))

	dl.On("Logf", "(%010d: %s) %s", []any{uint32(1), "A", "hello"})

	loggerA.Logf("%s", "hello")

	dl = mockDelegateLogger{}
	ctx = context.WithValue(context.Background(), testenv.TestingT, &dl)

	loggerB, ctx := LoggerFor(ctx)
	loggerB.Name("B")

	assert.Equal(t, loggerB, ctx.Value(loggerKey))

	dl.On("Logf", "(%010d: %s) %s", []any{uint32(2), "B", "hey"})

	loggerB.Log("hey")

	assert.NotEqual(t, loggerA.(*logger).id, loggerB.(*logger).id)
}
