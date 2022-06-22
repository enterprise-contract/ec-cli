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

// A stub implementation of the Kubernetes apiserver
package kubernetes

import (
	"context"
	"fmt"
	"os"

	"github.com/cucumber/godog"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/git"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/wiremock"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// stubApiserverRunning starts the stub apiserver using WireMock
func stubApiserverRunning(ctx context.Context) (context.Context, error) {
	return wiremock.StartWiremock(ctx)
}

// stubPolicy stubs a response from the apiserver to fetch a EnterpriseContractPolicy
// custom resource from the `acceptance` namespace with the given name and specification
// the specification part can be templated using ${...} notation and supports `GITHOST`
// variable substitution
// TODO: namespace support
func stubPolicy(ctx context.Context, name string, specification *godog.DocString) error {
	ns := "acceptance"
	return wiremock.StubFor(ctx, wiremock.Get(wiremock.URLPathEqualTo(fmt.Sprintf("/apis/appstudio.redhat.com/v1alpha1/namespaces/%s/enterprisecontractpolicies/%s", ns, name))).
		WillReturn(fmt.Sprintf(`{
				"apiVersion": "appstudio.redhat.com/v1alpha1",
				"kind": "EnterpriseContractPolicy",
				"metadata": {
				  "name": "%s",
				  "namespace": "%s"
				},
				"spec": %s
			  }`, name, ns, os.Expand(specification.Content, func(key string) string {
			if key == "GITHOST" {
				return git.GitHost(ctx)
			}

			return ""
		})),
			map[string]string{"Content-Type": "application/json"},
			200,
		))
}

// KubeConfig returns a valid kubeconfig configuration file in YAML format that
// points to the stubbed apiserver and uses no authentication
func KubeConfig(ctx context.Context) string {
	server := wiremock.Endpoint(ctx)

	cluster := "my-cluster"

	context := "my-context"

	kubeconfig := api.Config{
		CurrentContext: context,
		Clusters: map[string]*api.Cluster{
			cluster: {
				Server: server,
			},
		},
		Contexts: map[string]*api.Context{
			context: {
				Cluster: cluster,
			},
		},
	}

	b, err := clientcmd.Write(kubeconfig)
	if err != nil {
		panic(err)
	}

	return string(b)
}

// AddStepsTo adds Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^stub apiserver running$`, stubApiserverRunning)
	sc.Step(`^policy configuration named "([^"]*)" with specification$`, stubPolicy)
}
