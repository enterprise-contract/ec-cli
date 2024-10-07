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
	"sync"

	log "github.com/sirupsen/logrus"
)

// policyCacheKey is the key for PolicyCache values in Context.
// It's unexported to prevent external packages from using it.
var policyCacheKey = policyCacheKeyType{}

// Define an unexported type to prevent key collisions in context.
type policyCacheKeyType struct{}

// cacheEntry represents a single cache entry with a value and a sync.Once for initialization.
type cacheEntry struct {
	value string
	err   error
}

// KeyValuePair represents a key-value pair from the cache.
type KeyValuePair struct {
	Key   string
	Value string
}

// PolicyCache holds cached policy data using a thread-safe map.
type PolicyCache struct {
	Data sync.Map
}

// Get retrieves the value and error for the given key from the cache.
// It returns the value and true if found, or an empty string and false otherwise.
func (c *PolicyCache) Get(key string) (string, bool) {
	actual, ok := c.Data.Load(key)
	if !ok {
		return "", ok
	}
	entry, ok := actual.(*cacheEntry)
	if !ok {
		return "", ok
	}
	return entry.value, ok
}

// Set manually sets the value for a given key in the cache.
// It overwrites any existing value and error.
func (c *PolicyCache) Set(key string, value string, err error) {
	entry := &cacheEntry{
		value: value,
		err:   err,
	}
	c.Data.Store(key, entry)
}

// NewPolicyCache creates and returns a new PolicyCache instance.
func NewPolicyCache(ctx context.Context) (*PolicyCache, error) {
	cache, ok := ctx.Value(policyCacheKey).(*PolicyCache)
	if ok && cache != nil {
		return cache, nil
	}

	c, err := CreatePolicyCache()
	if err != nil {
		log.Debug("Failed to create PolicyCache")
		return nil, err
	}

	return c, nil
}

func CreatePolicyCache() (*PolicyCache, error) {
	return &PolicyCache{
		Data: sync.Map{},
	}, nil
}

// PolicyCacheFromContext retrieves the PolicyCache from the context.
// It returns the PolicyCache and true if found, or nil and false otherwise.
func PolicyCacheFromContext(ctx context.Context) (*PolicyCache, bool) {
	cache, ok := ctx.Value(policyCacheKey).(*PolicyCache)
	return cache, ok
}

// WithPolicyCache returns a new context with the provided PolicyCache added.
func WithPolicyCache(ctx context.Context, cache *PolicyCache) context.Context {
	return context.WithValue(ctx, policyCacheKey, cache)
}
