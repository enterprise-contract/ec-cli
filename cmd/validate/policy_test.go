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

package validate

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ValidatePolicyCmd(t *testing.T) {
	validate := func(ctx context.Context, policyConfiguration string) error {
		// Mock implementation of the validate function
		return nil
	}

	cmd := ValidatePolicyCmd(validate)

	t.Run("PreRunE", func(t *testing.T) {
		// Test PreRunE function
		err := cmd.PreRunE(cmd, []string{})
		assert.NoError(t, err)
	})

	t.Run("RunE", func(t *testing.T) {
		// Test RunE function
		err := cmd.RunE(cmd, []string{})
		assert.NoError(t, err)
	})
}

func Test_ValidatePolicyErrors(t *testing.T) {
	validate := func(ctx context.Context, policyConfiguration string) error {
		// Mock implementation of the validate function
		return errors.New("error")
	}

	cmd := ValidatePolicyCmd(validate)

	t.Run("PreRunE", func(t *testing.T) {
		// Test PreRunE function
		err := cmd.PreRunE(cmd, []string{})
		assert.NoError(t, err)
	})

	t.Run("RunE", func(t *testing.T) {
		// Test RunE function
		err := cmd.RunE(cmd, []string{})
		assert.ErrorContains(t, err, "policy configuration does not conform to the EnterpriseContractPolicy spec")
	})
}
