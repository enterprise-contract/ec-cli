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

package acceptance

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cucumber/godog"

	"github.com/hacbs-contract/ec-cli/acceptance/cli"
	"github.com/hacbs-contract/ec-cli/acceptance/conftest"
	"github.com/hacbs-contract/ec-cli/acceptance/crypto"
	"github.com/hacbs-contract/ec-cli/acceptance/git"
	"github.com/hacbs-contract/ec-cli/acceptance/image"
	"github.com/hacbs-contract/ec-cli/acceptance/kubernetes"
	"github.com/hacbs-contract/ec-cli/acceptance/pipeline"
	"github.com/hacbs-contract/ec-cli/acceptance/registry"
	"github.com/hacbs-contract/ec-cli/acceptance/rekor"
	"github.com/hacbs-contract/ec-cli/acceptance/tekton"
	"github.com/hacbs-contract/ec-cli/acceptance/testenv"
	"github.com/hacbs-contract/ec-cli/acceptance/wiremock"
)

// NOTE: flags need to be initialized with the package in order to be recognized
// a flag that can be set by running the test with "-args -persist" command line options
var persist = flag.Bool("persist", false, "persist the stubbed environment to facilitate debugging")

// run acceptance tests with the persisted environment
var restore = flag.Bool("restore", false, "restore last persisted environment")

var noColors = flag.Bool("no-colors", false, "disable colored output")

// specify a subset of scenarios to run filtering by given tags
var tags = flag.String("tags", "", "select scenarios to run based on tags")

// initializeScenario adds all steps and registers all hooks to the
// provided godog.ScenarioContext
func initializeScenario(sc *godog.ScenarioContext) {
	cli.AddStepsTo(sc)
	crypto.AddStepsTo(sc)
	git.AddStepsTo(sc)
	image.AddStepsTo(sc)
	kubernetes.AddStepsTo(sc)
	registry.AddStepsTo(sc)
	rekor.AddStepsTo(sc)
	tekton.AddStepsTo(sc)
	wiremock.AddStepsTo(sc)
	pipeline.AddStepsTo(sc)
	conftest.AddStepsTo(sc)

	sc.After(func(ctx context.Context, scenario *godog.Scenario, scenarioErr error) (context.Context, error) {
		_, err := testenv.Persist(ctx)
		return ctx, err
	})
}

// setupContext creates a Context prepopulated with the *testing.T and *persist
// values
func setupContext(t *testing.T) context.Context {
	ctx := context.WithValue(context.Background(), testenv.TestingT, t)
	ctx = context.WithValue(ctx, testenv.PersistStubEnvironment, *persist)
	ctx = context.WithValue(ctx, testenv.RestoreStubEnvironment, *restore)
	ctx = context.WithValue(ctx, testenv.NoColors, *noColors)

	return ctx
}

// TestFeatures launches all acceptance test scenarios running them
// in random order in parallel threads equal to the number of available
// cores
func TestFeatures(t *testing.T) {
	// change the directory to repository root, makes for easier paths
	if err := os.Chdir(".."); err != nil {
		t.Error(err)
	}

	featuresDir, err := filepath.Abs("features")
	if err != nil {
		t.Error(err)
	}

	opts := godog.Options{
		Format:         "pretty",
		Paths:          []string{featuresDir},
		Randomize:      -1,
		Concurrency:    runtime.NumCPU(),
		TestingT:       t,
		DefaultContext: setupContext(t),
		Tags:           *tags,
		NoColors:       *noColors,
	}

	suite := godog.TestSuite{
		ScenarioInitializer: initializeScenario,
		Options:             &opts,
	}

	if suite.Run() != 0 {
		t.Fatal("failure in acceptance tests")
	}
}
