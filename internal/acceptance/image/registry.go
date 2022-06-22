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

// TODO: perhaps move this to registry?
package image

import (
	"context"
	"fmt"

	"github.com/docker/go-connections/nat"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/log"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/testenv"
	"github.com/pkg/errors"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// the image we're using to launch the stub image registyr
const registryImage = "docker.io/registry:2.8.1"

type key int

// key to store the host:port of the stubbed registry in Context
const registryKey = key(0)

// startStubRegistry creates and starts the stub image registry
func startStubRegistry(ctx context.Context) (context.Context, error) {
	req := testenv.TestContainersRequest(ctx, testcontainers.ContainerRequest{
		Image:        registryImage,
		ExposedPorts: []string{"5000/tcp"},
		WaitingFor:   wait.ForHTTP("/v2/").WithPort(nat.Port("5000/tcp")),
	})

	registry, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           log.LoggerFor(ctx),
	})
	if err != nil {
		return ctx, err
	}

	port, err := registry.MappedPort(ctx, nat.Port("5000/tcp"))
	if err != nil {
		return ctx, err
	}

	return context.WithValue(ctx, registryKey, fmt.Sprintf("localhost:%d", port.Int())), nil
}

// ImageReferenceInStubRegistry returns a reference for a image constructed by concatenating
// the host:port/`name` where the name is formatted by the given format and arguments
func ImageReferenceInStubRegistry(ctx context.Context, format string, args ...interface{}) name.Reference {
	imageRef := StubRegistry(ctx) + "/" + fmt.Sprintf(format, args...)

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		panic(errors.Wrapf(err, "unable to parse image reference: %s", imageRef))
	}

	return ref
}

// StubRegistry returns the host:port of the stubbed registry from the Context
func StubRegistry(ctx context.Context) string {
	return ctx.Value(registryKey).(string)
}
