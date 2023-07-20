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

//go:build integration

package main

import (
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestCurrent(t *testing.T) {
	results := analysistest.RunWithSuggestedFixes(t, path.Join(analysistest.TestData(), "current"), &current)

	assert.Len(t, results, 1)

	result := results[0].Result
	assert.IsType(t, (*currentInfos)(nil), result)
	assert.Contains(t, result.(*currentInfos).info, "something/existing.go")
	assert.Len(t, result.(*currentInfos).info, 1)
	existing := result.(*currentInfos).info["something/existing.go"]

	assert.Equal(t, []string{"TE001", "TE002", "TE004"}, existing.errors)
	assert.Equal(t, "e", existing.name)
	assert.NotZero(t, existing.packagePos)
	assert.NotNil(t, existing.importNode)
	assert.NotNil(t, existing.varNode)
}

func TestReturns(t *testing.T) {
	analysistest.RunWithSuggestedFixes(t, path.Join(analysistest.TestData(), "returns"), &returns)
}
