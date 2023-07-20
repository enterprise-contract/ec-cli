// Copyright The Enterprise Contract Contributors
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

package logging

import (
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestEntry(t *testing.T) {
	assert.NotNil(t, logrusSink{}.entry())

	withName := logrusSink{name: "name"}.entry()
	assert.Equal(t, logrus.Fields{"name": "name"}, withName.Data)

	withKeyAndValue := logrusSink{fields: []any{"k", "v"}}.entry()
	assert.Equal(t, logrus.Fields{"k": "v"}, withKeyAndValue.Data)

	withNameKeyAndValue := logrusSink{name: "name", fields: []any{"k", "v"}}.entry()
	assert.Equal(t, logrus.Fields{"name": "name", "k": "v"}, withNameKeyAndValue.Data)
}

func TestToLevel(t *testing.T) {
	cases := map[int]logrus.Level{
		-1: logrus.DebugLevel,
		0:  logrus.InfoLevel,
		1:  logrus.WarnLevel,
		2:  logrus.ErrorLevel,
		3:  logrus.FatalLevel,
		4:  logrus.DebugLevel,
	}

	for given, expected := range cases {
		t.Run(fmt.Sprintf("case: %d -> %d", given, expected), func(t *testing.T) {
			assert.Equal(t, expected, toLevel(given))
		})
	}
}
