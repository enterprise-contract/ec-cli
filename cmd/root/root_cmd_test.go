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

package root

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGlobalTimeout(t *testing.T) {
	tests := []struct {
		name           string
		timeoutFlag    string
		expectedValue  time.Duration
		expectedString string
	}{
		{
			name:           "default timeout",
			timeoutFlag:    "",
			expectedValue:  5 * time.Minute,
			expectedString: "5m0s",
		},
		{
			name:           "custom timeout in hours",
			timeoutFlag:    "100h",
			expectedValue:  100 * time.Hour,
			expectedString: "100h0m0s",
		},
		{
			name:           "custom timeout in minutes",
			timeoutFlag:    "30m",
			expectedValue:  30 * time.Minute,
			expectedString: "30m0s",
		},
		{
			name:           "zero timeout",
			timeoutFlag:    "0",
			expectedValue:  0,
			expectedString: "0s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset globalTimeout to default value before each test
			globalTimeout = 5 * time.Minute

			cmd := NewRootCmd()
			if tt.timeoutFlag != "" {
				cmd.SetArgs([]string{"--timeout", tt.timeoutFlag})
			}

			// Execute the command to trigger flag parsing
			err := cmd.Execute()
			assert.NoError(t, err)

			// Verify the timeout value
			assert.Equal(t, tt.expectedValue, globalTimeout)
			assert.Equal(t, tt.expectedString, globalTimeout.String())
		})
	}
}
