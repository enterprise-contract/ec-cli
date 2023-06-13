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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/cucumber/godog"
	clr "github.com/doiit/picocolors"
	"golang.org/x/exp/maps"

	"github.com/enterprise-contract/ec-cli/acceptance/crypto"
	"github.com/enterprise-contract/ec-cli/acceptance/image"
	"github.com/enterprise-contract/ec-cli/acceptance/kubernetes/kind"
	"github.com/enterprise-contract/ec-cli/acceptance/kubernetes/stub"
	"github.com/enterprise-contract/ec-cli/acceptance/kubernetes/types"
	"github.com/enterprise-contract/ec-cli/acceptance/registry"
	"github.com/enterprise-contract/ec-cli/acceptance/snaps"
	"github.com/enterprise-contract/ec-cli/acceptance/testenv"
)

type key int

const (
	clusterStateKey = key(0) // we store the ClusterState struct under this key in Context and when persisted
	stopStateKey    = key(iota)
)

// ClusterState holds the Cluster used in the current Context
type ClusterState struct {
	cluster types.Cluster
}

func (c ClusterState) Key() any {
	return clusterStateKey
}

func (c ClusterState) Up(ctx context.Context) bool {
	// if the cluster implementation has been initialized and it claims the
	// cluster to be up
	return c.cluster != nil && c.cluster.Up(ctx)
}

func (c ClusterState) KubeConfig(ctx context.Context) (string, error) {
	if err := mustBeUp(ctx, c); err != nil {
		return "", err
	}

	return c.cluster.KubeConfig(ctx)
}

type startFunc func(context.Context) (context.Context, types.Cluster, error)

// startAndSetupState starts the cluster via the provided startFunc. The
// crosscutting concern of setting up the ClusterState in the Context and making
// sure we don't start the cluster multiple times per Context is handled here
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

// mustBeUp makes sure that the cluster is up, used by functions that require
// the cluster to be up
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

func createNamedSnapshot(ctx context.Context, name string, specification *godog.DocString) error {
	c := testenv.FetchState[ClusterState](ctx)

	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}

	return c.cluster.CreateNamedSnapshot(ctx, name, specification.Content)
}

func createPolicy(ctx context.Context, specification *godog.DocString) error {
	c := testenv.FetchState[ClusterState](ctx)

	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}

	return c.cluster.CreatePolicy(ctx, specification.Content)
}

func runTask(ctx context.Context, version, name string, params *godog.Table) error {
	return runTaskWithWorkspace(ctx, version, name, "", params)
}

func runTaskWithWorkspace(ctx context.Context, version, name, workspace string, params *godog.Table) error {
	c := testenv.FetchState[ClusterState](ctx)

	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}

	taskParams := map[string]string{}
	for _, row := range params.Rows {
		taskParams[row.Cells[0].Value] = row.Cells[1].Value
	}

	return c.cluster.RunTask(ctx, version, name, workspace, taskParams)
}

func theTaskShouldSucceed(ctx context.Context) error {
	return processTaskCompletedStatus(ctx, true)
}

func theTaskShouldFail(ctx context.Context) error {
	return processTaskCompletedStatus(ctx, false)
}

func processTaskCompletedStatus(ctx context.Context, want bool) error {
	c := testenv.FetchState[ClusterState](ctx)

	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}

	got, err := c.cluster.AwaitUntilTaskIsDone(ctx)
	if err != nil {
		return err
	}

	if got != want {
		if err := logTaskOutput(ctx, *c); err != nil {
			return err
		}
		return fmt.Errorf("the TaskRun did not complete as expected: want=%v, got=%v", want, got)
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

	// TODO, when the task fails and test state is persisted add some debugging
	// lines here to help debug, e.g. `export
	// KUBECONFIG=$TMPDIR/ec-acceptance.../kubeconfig`, set the current
	// namespace with: `kubectl config set-context --current --namespace
	// acceptance-...`

	fmt.Println(output)
	return nil
}

func taskLogsShouldMatchTheSnapshot(ctx context.Context, stepName string) error {
	c := testenv.FetchState[ClusterState](ctx)

	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}

	info, err := c.cluster.TaskInfo(ctx)
	if err != nil {
		return err
	}

	r, err := c.cluster.Registry(ctx)
	if err != nil {
		return err
	}

	vars := map[string]string{
		"REGISTRY": r,
	}

	publicKeys := crypto.PublicKeysFrom(ctx)
	for name, key := range publicKeys {
		// account for various indentations
		vars[fmt.Sprintf("__%s_PUBLIC_KEY", name)] = indent(key, 2)
		vars[fmt.Sprintf("____%s_PUBLIC_KEY", name)] = indent(key, 4)
	}

	hashes, err := registry.AllHashes(ctx)
	if err != nil {
		return err
	}

	for repositoryAndTag, hash := range hashes {
		vars[fmt.Sprintf("REGISTRY_%s_HASH", repositoryAndTag)] = hash
	}

	maps.Copy(vars, image.RawAttestationSignaturesFrom(ctx))
	maps.Copy(vars, image.RawImageSignaturesFrom(ctx))

	v, err := testenv.CLIVersion(ctx)
	if err != nil {
		return err
	}

	vars["EC_VERSION"] = v

	for _, step := range info.Steps {
		if step.Name == stepName {
			return snaps.MatchSnapshot(ctx, step.Name, step.Logs, vars)
		}
	}

	return nil
}

func taskResultsShouldMatchTheSnapshot(ctx context.Context) error {
	c := testenv.FetchState[ClusterState](ctx)

	if err := mustBeUp(ctx, *c); err != nil {
		return err
	}

	info, err := c.cluster.TaskInfo(ctx)
	if err != nil {
		return err
	}

	j, err := json.Marshal(info.Results)
	if err != nil {
		return err
	}

	return snaps.MatchSnapshot(ctx, "results", string(j), nil)
}

func indent(str string, n int) string {
	idnt := strings.Repeat(" ", n)

	lines := strings.Split(str, "\n")

	return idnt + strings.TrimSuffix(strings.Join(lines, "\n"+idnt), "\n"+idnt)
}

// AddStepsTo adds cluster-related steps to the context
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^a stub cluster running$`, startAndSetupState(stub.Start))
	sc.Step(`^a cluster running$`, startAndSetupState(kind.Start))
	sc.Step(`^a working namespace$`, createNamespace)
	sc.Step(`^policy configuration named "([^"]*)" with specification$`, createNamedPolicy)
	sc.Step(`^a cluster policy with content:$`, createPolicy)
	sc.Step(`^version ([\d.]+) of the task named "([^"]*)" is run with parameters:$`, runTask)
	sc.Step(`^version ([\d.]+) of the task named "([^"]*)" with workspace "([^"]*)" is run with parameters:$`, runTaskWithWorkspace)
	sc.Step(`^the task should succeed$`, theTaskShouldSucceed)
	sc.Step(`^the task should fail$`, theTaskShouldFail)
	sc.Step(`^an Snapshot named "([^"]*)" with specification$`, createNamedSnapshot)
	sc.Step(`^the task logs for step "([^"]*)" should match the snapshot$`, taskLogsShouldMatchTheSnapshot)
	sc.Step(`^the task results should match the snapshot$`, taskResultsShouldMatchTheSnapshot)
	// stop usage of the cluster once a test is done, godog will call this
	// function on failure and on the last step, so more than once if the
	// failure is not on the last step and once if there was no failure or the
	// failure was on the last step
	sc.After(func(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		if ctx.Value(stopStateKey) == nil {
			ctx = context.WithValue(ctx, stopStateKey, true)
		} else {
			// we did this already
			return ctx, nil
		}

		if !testenv.HasState[ClusterState](ctx) {
			return ctx, nil
		}

		c := testenv.FetchState[ClusterState](ctx)

		if !c.cluster.Up(ctx) {
			return ctx, nil
		}

		return c.cluster.Stop(ctx)
	})

}

func InitializeSuite(ctx context.Context, tsc *godog.TestSuiteContext) {
	tsc.AfterSuite(func() {
		if !testenv.Persisted(ctx) {
			kind.Destroy(ctx)
		}
	})
}
