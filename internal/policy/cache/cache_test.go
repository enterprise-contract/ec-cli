// Copyright The Enterprise Contract Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicyCache_Get(t *testing.T) {
	ctx := context.Background()
	cache, err := NewPolicyCache(ctx)
	if err != nil {
		t.Errorf("Error creating cache: %v", err)
	}

	// Test case: Key does not exist
	value, ok := cache.Get("nonexistent")
	assert.False(t, ok)
	assert.Equal(t, "", value)

	// Test case: Key exists
	cache.Set("existing", "value", nil)
	value, ok = cache.Get("existing")
	assert.True(t, ok)
	assert.Equal(t, "value", value)

	// Test case: Key exists but with a different type
	cache.Data.Store("wrongtype", "string value")
	value, ok = cache.Get("wrongtype")
	assert.False(t, ok)
	assert.Equal(t, "", value)
}
func TestPolicyCacheFromContext(t *testing.T) {
	ctx := context.Background()
	cache, err := NewPolicyCache(ctx)
	if err != nil {
		t.Errorf("Error creating cache: %v", err)
	}

	// Test case: PolicyCache not in context
	retrievedCache, ok := PolicyCacheFromContext(ctx)
	assert.False(t, ok)
	assert.Nil(t, retrievedCache)

	// Test case: PolicyCache in context
	ctxWithCache := WithPolicyCache(ctx, cache)
	retrievedCache, ok = PolicyCacheFromContext(ctxWithCache)
	assert.True(t, ok)
	assert.Equal(t, cache, retrievedCache)
}
