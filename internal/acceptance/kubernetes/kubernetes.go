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

package kubernetes

import (
	"context"
	"errors"

	"github.com/cucumber/godog"

	"github.com/hacbs-contract/ec-cli/internal/acceptance/kubernetes/stub"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/kubernetes/types"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/testenv"
)

type key int

const clusterStateKey = key(0) // we store the ClusterState struct under this key in Context and when persisted

type ClusterState struct {
	cluster types.Cluster
}

func (c ClusterState) Key() any {
	return clusterStateKey
}

func (c ClusterState) Up(ctx context.Context) bool {
	return c.cluster != nil && c.cluster.Up(ctx)
}

func (c ClusterState) KubeConfig(ctx context.Context) (string, error) {
	if err := mustBeUp(ctx, c); err != nil {
		return "", err
	}

	return c.cluster.KubeConfig(ctx)
}

type startFunc func(context.Context) (context.Context, types.Cluster, error)

func startAndSetupState(start startFunc) func(context.Context) (context.Context, error) {
	return func(ctx context.Context) (context.Context, error) {
		var c = &ClusterState{}
		ctx, err := testenv.SetupState(ctx, &c)
		if err != nil {
			return ctx, err
		}

		if c.Up(ctx) {
			return ctx, nil
		}

		ctx, c.cluster, err = start(ctx)

		return ctx, err
	}
}

func mustBeUp(ctx context.Context, c ClusterState) error {
	if !c.Up(ctx) {
		return errors.New("cluster has not been started, use `Given a <stub?> cluster running")
	}

	return nil
}

func createNamedPolicy(ctx context.Context, name string, specification *godog.DocString) error {
	c := testenv.FetchState[ClusterState](ctx)

	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}

	return c.cluster.CreateNamedPolicy(ctx, name, specification.Content)
}

// AddStepsTo adds cluster-related steps to the context
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^a stub cluster running$`, startAndSetupState(stub.Start))
	sc.Step(`^policy configuration named "([^"]*)" with specification$`, createNamedPolicy)

	// stops the cluster unless the environment is persisted, the cluster state
	// is nonexistent or the cluster wasn't started
	sc.After(func(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		if testenv.Persisted(ctx) {
			return ctx, nil
		}

		if !testenv.HasState[ClusterState](ctx) {
			return ctx, nil
		}

		c := testenv.FetchState[ClusterState](ctx)

		if !c.cluster.Up(ctx) {
			return ctx, nil
		}

		return ctx, c.cluster.Stop(ctx)
	})
}
