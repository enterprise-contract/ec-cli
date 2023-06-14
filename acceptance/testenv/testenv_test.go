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

package testenv

import (
	"context"
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

type key int

type stateful struct {
	Number int
	Str    string
}

const (
	statefulKey key = iota
	anotherKey
	initializingKey
)

func (s stateful) Key() any {
	return statefulKey
}

type another struct {
	Val float32
}

func (a another) Key() any {
	return anotherKey
}

type initializing struct {
	initialized bool
}

func (i initializing) Key() any {
	return initializingKey
}

func (i *initializing) Initialize() {
	i.initialized = true
}

func Test_SetupStatePersisted(t *testing.T) {
	var s *stateful
	ctx, err := SetupState(context.TODO(), &s)

	assert.NoError(t, err)

	expected := stateful{Number: 0, Str: ""}
	assert.Equal(t, expected, *s)
	assert.Equal(t, &expected, FetchState[stateful](ctx))
}

func Test_SetupStatePersistedTwoTypes(t *testing.T) {
	var s *stateful
	ctx, err := SetupState(context.TODO(), &s)

	assert.NoError(t, err)

	var a *another
	ctx, err = SetupState(ctx, &a)

	assert.NoError(t, err)

	expectedStateful := stateful{Number: 0, Str: ""}
	assert.Equal(t, expectedStateful, *s)
	assert.Equal(t, &expectedStateful, FetchState[stateful](ctx))

	expectedAnother := another{Val: 0}
	assert.Equal(t, expectedAnother, *a)
	assert.Equal(t, &expectedAnother, FetchState[another](ctx))
}

func Test_SetupStateExistingValue(t *testing.T) {
	existing := another{Val: 2.5}

	ctx := context.WithValue(context.TODO(), persistedEnv, &map[string]any{
		"testenv.key.1": &existing,
	})

	var s *stateful
	ctx, err := SetupState(ctx, &s)

	assert.NoError(t, err)

	var a *another
	ctx, err = SetupState(ctx, &a)

	assert.NoError(t, err)

	expectedStateful := stateful{Number: 0, Str: ""}
	assert.Equal(t, expectedStateful, *s)
	assert.Equal(t, &expectedStateful, FetchState[stateful](ctx))

	expectedAnother := another{Val: 2.5}
	assert.Equal(t, expectedAnother, *a)
	assert.Equal(t, &expectedAnother, FetchState[another](ctx))
}

func Test_SetupStateMutateExistingValue(t *testing.T) {
	var s1 *stateful
	ctx, err := SetupState(context.TODO(), &s1)

	assert.NoError(t, err)
	assert.Equal(t, stateful{Number: 0, Str: ""}, *s1)
	s1.Number = 42

	expectedStateful := stateful{Number: 42, Str: ""}
	assert.Equal(t, &expectedStateful, FetchState[stateful](ctx))

	var s2 *stateful
	ctx, err = SetupState(ctx, &s2)

	assert.NoError(t, err)
	assert.Equal(t, stateful{Number: 42, Str: ""}, *s2)
	s2.Number = 101

	expectedStateful = stateful{Number: 101, Str: ""}
	assert.Equal(t, &expectedStateful, FetchState[stateful](ctx))
}

func Test_SetupStateRestoreValue(t *testing.T) {
	loader = func(filename string) ([]byte, error) {
		return []byte(`{"testenv.key.0": {"number": 3, "str": "hi"}}`), nil
	}

	ctx := context.WithValue(context.TODO(), RestoreStubEnvironment, true)

	var s *stateful
	ctx, err := SetupState(ctx, &s)

	assert.NoError(t, err)

	expectedStateful := stateful{Number: 3, Str: "hi"}
	assert.Equal(t, expectedStateful, *s)
	assert.Equal(t, &expectedStateful, FetchState[stateful](ctx))
}

func Test_Persist(t *testing.T) {
	var persisted string
	persister = func(filename string, data []byte, perm fs.FileMode) error {
		persisted = string(data)
		return nil
	}

	ctx := context.WithValue(context.TODO(), PersistStubEnvironment, true)
	ctx = context.WithValue(ctx, persistedEnv, &map[string]any{
		persistedKey(&stateful{}): &stateful{
			Number: 42,
			Str:    "dogs",
		},
		persistedKey(&another{}): &another{
			Val: 12,
		},
	})

	persisting, err := Persist(ctx)

	assert.True(t, persisting)
	assert.NoError(t, err)

	assert.JSONEq(t, `{
		"testenv.key.0": {
			"Number": 42,
			"Str": "dogs"
		},
		"testenv.key.1": {
			"Val": 12
		}
	}`, persisted)
}

func Test_PersistOff(t *testing.T) {
	var persisted bool
	persister = func(filename string, data []byte, perm fs.FileMode) error {
		persisted = true
		return nil
	}

	ctx := context.WithValue(context.TODO(), PersistStubEnvironment, false)

	persisting, err := Persist(ctx)

	assert.NoError(t, err)
	assert.False(t, persisting)
	assert.False(t, persisted)
}

func Test_TestContainersRequest(t *testing.T) {
	cases := []struct {
		name       string
		persisted  bool
		req        testcontainers.ContainerRequest
		autoRemove bool
		skipReaper string
	}{
		{
			name:       "not persisted",
			persisted:  false,
			req:        testcontainers.ContainerRequest{},
			autoRemove: true,
			skipReaper: "",
		},
		{
			name:      "not persisted - changed defaults",
			persisted: false,
			req: testcontainers.ContainerRequest{
				AutoRemove: false,
			},
			autoRemove: true,
			skipReaper: "",
		},
		{
			name:       "persisted",
			persisted:  true,
			req:        testcontainers.ContainerRequest{},
			autoRemove: false,
			skipReaper: "true",
		},
		{
			name:      "persisted - change defaults",
			persisted: true,
			req: testcontainers.ContainerRequest{
				AutoRemove: true,
			},
			autoRemove: false,
			skipReaper: "true",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			os.Clearenv()
			ctx := context.WithValue(context.TODO(), PersistStubEnvironment, c.persisted)

			out := TestContainersRequest(ctx, c.req)

			assert.Equal(t, c.autoRemove, out.AutoRemove, "AutoRemove")
			assert.Equal(t, c.skipReaper, os.Getenv("TESTCONTAINERS_RYUK_DISABLED"), "SkipReaper")
		})
	}
}

func Test_ColorFlag(t *testing.T) {
	assert.False(t, NoColorOutput(context.TODO()))

	ctx := context.WithValue(context.TODO(), NoColors, false)
	assert.False(t, NoColorOutput(ctx))

	ctx = context.WithValue(context.TODO(), NoColors, true)
	assert.True(t, NoColorOutput(ctx))
}

func TestInitializingState(t *testing.T) {
	var i *initializing
	ctx, err := SetupState(context.Background(), &i)
	require.NoError(t, err)

	assert.Equal(t, true, i.initialized)

	i2 := FetchState[initializing](ctx)

	assert.Equal(t, true, i2.initialized)
}
