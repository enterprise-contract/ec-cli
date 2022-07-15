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

// Package registry is a stub implementation of a container registry
package registry

import (
	"context"
	"fmt"

	"github.com/cucumber/godog"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/hacbs-contract/ec-cli/internal/acceptance/log"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/testenv"
)

// the image we're using to launch the stub image registry
const registryImage = "docker.io/registry:2.8.1"

type key int

// key to store the host:port of the stubbed registry in Context and persisted environment
const registryStateKey = key(0)

type registryState struct {
	HostAndPort string
}

func (g registryState) Key() any {
	return registryStateKey
}

func (g registryState) Up() bool {
	return g.HostAndPort != ""
}

// startStubRegistry creates and starts the stub image registry
func startStubRegistry(ctx context.Context) (context.Context, error) {
	var state *registryState
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if state.Up() {
		return ctx, nil
	}

	req := testenv.TestContainersRequest(ctx, testcontainers.ContainerRequest{
		Image:        registryImage,
		ExposedPorts: []string{"5000/tcp"},
		WaitingFor:   wait.ForHTTP("/v2/").WithPort("5000/tcp"),
	})

	registry, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           log.LoggerFor(ctx),
	})
	if err != nil {
		return ctx, err
	}

	port, err := registry.MappedPort(ctx, "5000/tcp")
	if err != nil {
		return ctx, err
	}

	state.HostAndPort = fmt.Sprintf("localhost:%d", port.Int())

	return ctx, nil
}

// ImageReferenceInStubRegistry returns a reference for an image constructed by concatenating
// the host:port/`name` where the name is formatted by the given format and arguments
func ImageReferenceInStubRegistry(ctx context.Context, format string, args ...interface{}) (name.Reference, error) {
	registry, err := StubRegistry(ctx)
	if err != nil {
		return nil, err
	}

	imageRef := registry + "/" + fmt.Sprintf(format, args...)

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		panic(errors.Wrapf(err, "unable to parse image reference: %s", imageRef))
	}

	return ref, nil
}

// StubRegistry returns the host:port of the stubbed registry from the Context
func StubRegistry(ctx context.Context) (string, error) {
	state := testenv.FetchState[registryState](ctx)

	if !state.Up() {
		return "", errors.New("no state setup, did you start the registry stub server?")
	}

	return state.HostAndPort, nil
}

func IsRunning(ctx context.Context) bool {
	if !testenv.HasState[registryState](ctx) {
		return false
	}

	state := testenv.FetchState[registryState](ctx)
	return state.Up()
}

// AddStepsTo adds Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^stub registry running$`, startStubRegistry)
}
