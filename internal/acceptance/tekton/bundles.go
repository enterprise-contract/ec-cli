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

package tekton

import (
	"context"

	"github.com/cucumber/godog"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/hacbs-contract/ec-cli/internal/acceptance/registry"
)

func createTektonBundle(ctx context.Context, name string, data *godog.Table) (context.Context, error) {
	img, err := random.Image(4096, 2)
	if err != nil {
		return ctx, err
	}

	ref, err := registry.ImageReferenceInStubRegistry(ctx, name)
	if err != nil {
		return ctx, err
	}

	err = remote.Write(ref, img)
	if err != nil {
		return ctx, err
	}

	return ctx, nil
}

func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^a tekton bundle image named "([^"]*)" containing$`, createTektonBundle)
}
