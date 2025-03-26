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

//go:build unit || integration

// The contents of this file are meant to assist in writing unit tests. It requires the "unit" build
// tag which is not included when building the ec binary.
package utils

import (
	"crypto/sha256"
	"fmt"
)

// WithDigest appends a digest to the given image reference.
func WithDigest(ref string) string {
	checksum := sha256.New()
	checksum.Write([]byte(ref))
	return fmt.Sprintf("%s@sha256:%x", ref, checksum.Sum(nil))
}
