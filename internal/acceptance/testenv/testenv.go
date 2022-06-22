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

// Test environment utilities
package testenv

import (
	"context"

	"github.com/testcontainers/testcontainers-go"
)

type testEnv int

// Key we use to lookup the `persisted` flag, which pass it through the
// Context to prevent a package dependency cycle
const PersistStubEnvironment testEnv = 0

// Persisted returns true if the test environment persistes after the test has finished
func Persisted(ctx context.Context) bool {
	persist, ok := ctx.Value(PersistStubEnvironment).(bool)

	return ok && persist
}

// TestContainersRequest modifies the req to keep the container running after the test if PersistStubEnvironment is set to true in the ctx
func TestContainersRequest(ctx context.Context, req testcontainers.ContainerRequest) testcontainers.ContainerRequest {
	if Persisted(ctx) {
		req.AutoRemove = false
		req.SkipReaper = true
	}

	return req
}
