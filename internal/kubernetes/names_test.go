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

//go:build unit

package kubernetes

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func Test_NamespacedName(t *testing.T) {
	cases := []struct {
		test       string
		name       string
		kubeconfig string
		overrides  *clientcmd.ConfigOverrides
		expected   *types.NamespacedName
		err        string
	}{
		{
			test: "with namespace",
			name: "namespace/name",
			expected: &types.NamespacedName{
				Name:      "name",
				Namespace: "namespace",
			},
		},
		{
			test: "without namespace, with .kube/config",
			name: "name",
			kubeconfig: `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://api.test
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    namespace: test
  name: test-context
current-context: test-context`,
			expected: &types.NamespacedName{
				Name:      "name",
				Namespace: "test",
			},
		},
		{
			test: "without namespace, in-cluster",
			name: "name",
			overrides: &clientcmd.ConfigOverrides{
				Context: api.Context{
					Namespace: "test",
				},
			},
			expected: &types.NamespacedName{
				Name:      "name",
				Namespace: "test",
			},
		},
		{
			test:       "failure fetching namespace",
			name:       "name",
			kubeconfig: "wrong-format",
			err:        "cannot unmarshal",
		},
	}

	for _, c := range cases {
		t.Run(c.test, func(t *testing.T) {
			t.Setenv("KUBECONFIG", "/non/existent/path")
			if c.kubeconfig != "" {
				kubeconfig := path.Join(t.TempDir(), "KUBECONFIG")
				kubeconfigFile, err := os.Create(kubeconfig)
				assert.NoError(t, err)
				defer kubeconfigFile.Close()
				t.Cleanup(func() {
					os.Remove(kubeconfig)
				})
				_, err = kubeconfigFile.WriteString(c.kubeconfig)
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv("KUBECONFIG", kubeconfig)
			}
			if c.overrides == nil {
				overrides = clientcmd.ConfigOverrides{}
			} else {
				overrides = *c.overrides
			}

			n, err := NamespacedName(c.name)
			if c.err == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.ErrorContains(t, err, c.err)
			}
			assert.Equal(t, c.expected, n)
		})
	}
}
