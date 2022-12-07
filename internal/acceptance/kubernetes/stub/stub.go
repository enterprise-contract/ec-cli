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

package stub

import (
	"context"
	"fmt"
	"os"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	"github.com/hacbs-contract/ec-cli/internal/acceptance/git"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/kubernetes/types"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/wiremock"
)

type stubCluster struct {
}

// stubApiserverRunning starts the stub apiserver using WireMock
func Start(ctx context.Context) (context.Context, types.Cluster, error) {
	ctx, err := wiremock.StartWiremock(ctx)

	return ctx, stubCluster{}, err
}

// stubPolicy stubs a response from the apiserver to fetch a EnterpriseContractPolicy
// custom resource from the `acceptance` namespace with the given name and specification
// the specification part can be templated using ${...} notation and supports `GITHOST`
// variable substitution
// TODO: namespace support
func (s stubCluster) CreateNamedPolicy(ctx context.Context, name string, specification string) error {
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
			  }`, name, ns, os.Expand(specification, func(key string) string {
			if key == "GITHOST" {
				return git.Host(ctx)
			}

			return ""
		})),
			map[string]string{"Content-Type": "application/json"},
			200,
		))
}

func (s stubCluster) CreateNamespace(ctx context.Context) (context.Context, error) {
	// no-op, we can record or stub any namespace API calls if/when needed
	return ctx, nil
}

// KubeConfig returns a valid kubeconfig configuration file in YAML format that
// points to the stubbed apiserver and uses no authentication
func (s stubCluster) KubeConfig(ctx context.Context) (string, error) {
	server, err := wiremock.Endpoint(ctx)
	if err != nil {
		return "", err
	}

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
		return "", err
	}

	return string(b), nil
}

func (s stubCluster) Up(ctx context.Context) bool {
	return wiremock.IsRunning(ctx)
}

func (s stubCluster) Stop(ctx context.Context) error {
	return nil
}
