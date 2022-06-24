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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/testcontainers/testcontainers-go"
)

type testEnv int

// Key we use to lookup the `persisted` flag, which pass it through the
// Context to prevent a package dependency cycle
const (
	PersistStubEnvironment testEnv = iota
	RestoreStubEnvironment
	NoColors
	persistedEnv

	persistedFile = ".persisted"
)

var loader = ioutil.ReadFile
var persister = ioutil.WriteFile

// Persist persists the environment stored in context in a ".persisted" file as JSON
func Persist(ctx context.Context) (bool, error) {
	if !Persisted(ctx) {
		return false, nil
	}

	values, ok := ctx.Value(persistedEnv).(*map[string]any)
	if !ok {
		return true, errors.New("did not find expected map type in Context for the persistedEnv value")
	}

	b, err := json.Marshal(values)
	if err != nil {
		return true, fmt.Errorf("unable to store JSON data in .persisted file: %v", err.Error())
	}

	err = persister(persistedFile, b, 0644)
	if err != nil {
		return true, fmt.Errorf("unable to write to %s file: %v", persistedFile, err.Error())
	}

	return true, nil
}

// Persisted returns true if the test environment persistes after the test has finished
func Persisted(ctx context.Context) bool {
	persist, ok := ctx.Value(PersistStubEnvironment).(bool)

	// if we're either not persisting or we ran in restored environment, this is
	// to allow the environment to persist and not require both -persist and -restore
	// to be specified, i.e. when running with -restore, -persist is assumed
	return ok && persist || Restored(ctx)
}

// Restored returns true if the test environment is restored from the last persisted environment
func Restored(ctx context.Context) bool {
	restore, ok := ctx.Value(RestoreStubEnvironment).(bool)

	return ok && restore
}

// RestoreValue returns the value associated with the given key from the last perserved environment
func restoreInto(key string, val any) error {
	b, err := loader(persistedFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}

	var j map[string]json.RawMessage

	if err = json.Unmarshal(b, &j); err != nil {
		return err
	}

	if err = json.Unmarshal(j[key], &val); err != nil {
		return err
	}

	return nil
}

// WithState marks a struct that holds some state under a specific key
type WithState interface {
	Key() any
}

// persistedKey constructs a key in the form of type.value
func persistedKey[S WithState](state S) string {
	key := state.Key()

	return fmt.Sprintf("%T.%v", key, key)
}

// SetupState initializes the given state S and stores it in Context under S.Key(), if invoked
// twice for the same S.Key() the state will be set to the existing value from Context. If the
// test environment is being restored, values from the persisted file will be loaded.
func SetupState[S WithState](ctx context.Context, state **S) (context.Context, error) {
	p := ctx.Value(persistedEnv)

	if p == nil {
		p = &map[string]any{}
	}

	// we need to new() to be able to invoke S.Key()
	newS := new(S)
	key := persistedKey(*newS)

	store := (*p.(*map[string]any))

	existing := store[key]

	if existing == nil {
		*state = newS
	} else {
		*state = existing.(*S)
	}

	store[key] = *state

	if Restored(ctx) {
		if err := restoreInto(key, &state); err != nil {
			return ctx, err
		}
	}

	return context.WithValue(ctx, persistedEnv, p), nil
}

// FetchState fetches the state from the Context stored under S.Key()
func FetchState[S WithState](ctx context.Context) *S {
	p := ctx.Value(persistedEnv)
	if p == nil {
		panic("need to invoke SetupState at least once")
	}

	newS := *new(S)
	key := persistedKey(newS)

	store := (*p.(*map[string]any))

	state := store[key]
	if state == nil {
		panic(fmt.Sprintf("no state found for key %s, make sure to invoke SetupState for %T first", key, newS))
	}

	return state.(*S)
}

// NoColorOutput returns true if the output produced should not contain colors, which is
// useful when a terminal or medium can't interpret ANSI colors
func NoColorOutput(ctx context.Context) bool {
	noColors, ok := ctx.Value(NoColors).(bool)

	return ok && noColors
}

// TestContainersRequest modifies the req to keep the container running after the test if PersistStubEnvironment is set to true in the ctx
func TestContainersRequest(ctx context.Context, req testcontainers.ContainerRequest) testcontainers.ContainerRequest {
	persisted := Persisted(ctx)

	req.AutoRemove = !persisted
	req.SkipReaper = persisted

	return req
}
