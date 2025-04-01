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

// The contents of this file are meant to assist in writing unit tests. It requires the "unit" build
// tag which is not included when building the ec binary.
package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetTestFulcioRoots(t *testing.T) {
	SetTestFulcioRoots(t)
	certsPath := os.Getenv("SIGSTORE_ROOT_FILE")
	assert.NotEmpty(t, certsPath)
	certs, err := os.ReadFile(certsPath)
	assert.NoError(t, err)
	assert.Equal(t, TestFulcioRootCert+TestFulcioRootIntermediate, string(certs))
}

func TestSetTestCTLogPublicKey(t *testing.T) {
	SetTestCTLogPublicKey(t)
	pubKeyPath := os.Getenv("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE")
	assert.NotEmpty(t, pubKeyPath)
	pubKey, err := os.ReadFile(pubKeyPath)
	assert.NoError(t, err)
	assert.Equal(t, TestCTLogPublicKey, string(pubKey))
}

func TestSetTestRekorPublicKey(t *testing.T) {
	SetTestRekorPublicKey(t)
	pubKeyPath := os.Getenv("SIGSTORE_REKOR_PUBLIC_KEY")
	assert.NotEmpty(t, pubKeyPath)
	pubKey, err := os.ReadFile(pubKeyPath)
	assert.NoError(t, err)
	assert.Equal(t, TestRekorPublicKey, string(pubKey))
}
