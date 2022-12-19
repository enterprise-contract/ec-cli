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
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/cucumber/godog"
	clr "github.com/doiit/picocolors"

	"github.com/hacbs-contract/ec-cli/internal/acceptance/kubernetes/kind"
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

func createNamespace(ctx context.Context) (context.Context, error) {
	c := testenv.FetchState[ClusterState](ctx)

	if err := mustBeUp(ctx, *c); err != nil {
		return ctx, err
	}

	return c.cluster.CreateNamespace(ctx)
}

func createNamedPolicy(ctx context.Context, name string, specification *godog.DocString) error {
	c := testenv.FetchState[ClusterState](ctx)

	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}

	return c.cluster.CreateNamedPolicy(ctx, name, specification.Content)
}

func createPolicy(ctx context.Context, specification *godog.DocString) error {
	c := testenv.FetchState[ClusterState](ctx)

	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}

	return c.cluster.CreatePolicy(ctx, specification.Content)
}

func runTask(ctx context.Context, version string, params *godog.Table) error {
	c := testenv.FetchState[ClusterState](ctx)

	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}

	taskParams := map[string]string{}
	for _, row := range params.Rows {
		taskParams[row.Cells[0].Value] = row.Cells[1].Value
	}

	return c.cluster.RunTask(ctx, version, taskParams)
}

func theTaskShouldSucceed(ctx context.Context) error {
	c := testenv.FetchState[ClusterState](ctx)

	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}

	successful, err := c.cluster.AwaitUntilTaskIsSuccessful(ctx)
	if err != nil {
		return err
	}

	if !successful {
		if err := logTaskOutput(ctx, *c); err != nil {
			return err
		}

		return errors.New("the TaskRun did not succeed")
	}

	return nil
}

func logTaskOutput(ctx context.Context, c ClusterState) error {
	info, err := c.cluster.TaskInfo(ctx)
	if err != nil {
		return err
	}

	noColors := testenv.NoColorOutput(ctx)
	if clr.SUPPORT_COLOR != !noColors {
		clr.SUPPORT_COLOR = !noColors
	}

	output := &strings.Builder{}
	outputSegment := func(name string, v any) {
		output.WriteString("\n\n")
		output.WriteString(clr.Underline(clr.Bold(name)))
		output.WriteString(fmt.Sprintf("\n%v", v))
	}

	var buffy bytes.Buffer
	w := tabwriter.NewWriter(&buffy, 10, 1, 2, ' ', 0)

	fmt.Fprintf(w, "%s\t%s\n", clr.Bold("Namespace"), info.Namespace)
	fmt.Fprintf(w, "%s\t%s\n", clr.Bold("Name"), info.Name)
	fmt.Fprintf(w, "%s\t%s", clr.Bold("Status"), info.Status)
	w.Flush()
	outputSegment("TaskRun", buffy.String())

	buffy.Reset()
	fmt.Fprintf(w, "%s\t%s\n", clr.Bold("Name"), clr.Bold("Value"))
	for n, v := range info.Params {
		fmt.Fprintf(w, "%s\t%v\n", n, v)
	}
	w.Flush()
	outputSegment("Parameters", buffy.String())

	buffy.Reset()
	for _, step := range info.Steps {
		outputSegment(fmt.Sprintf("Step \"%s\"", clr.Bold(step.Name)), fmt.Sprintf("%s  %s\n----- Logs -----\n%s\n----- /Logs -----", clr.Bold("Status"), step.Status, step.Logs))
	}
	w.Flush()

	fmt.Println(output)
	return nil
}

// AddStepsTo adds cluster-related steps to the context
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^a stub cluster running$`, startAndSetupState(stub.Start))
	sc.Step(`^a cluster running$`, startAndSetupState(kind.Start))
	sc.Step(`^a working namespace$`, createNamespace)
	sc.Step(`^policy configuration named "([^"]*)" with specification$`, createNamedPolicy)
	sc.Step(`^a cluster policy with content:$`, createPolicy)
	sc.Step(`^version ([\d.]+) of the task is run with parameters:$`, runTask)
	sc.Step(`^the task should succeed$`, theTaskShouldSucceed)

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
