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
	"strings"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
)

// NamespacedName constructs a NamespacedName from the provided name by either
// splitting it with the default spearator or augmenting it with the namespace
// selected in the Kubernetes Context configuration.
func NamespacedName(name string) (*types.NamespacedName, error) {
	policyParts := strings.SplitN(name, string(types.Separator), 2)
	if len(policyParts) == 2 {
		return &types.NamespacedName{
			Namespace: policyParts[0],
			Name:      policyParts[1],
		}, nil
	}

	namespace, err := currentNamespace()
	if err != nil {
		log.Debug("Failed to get current k8s namespace!")
		return nil, err
	}
	log.Debugf("Found k8s namespace %s", namespace)

	return &types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}, nil
}

// used in tests to provide an override simulating in-cluster configuration
var overrides = clientcmd.ConfigOverrides{}

// currentNamespace returns the namespace of the current context if one is set.
func currentNamespace() (string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()

	clientCfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &overrides)

	if namespace, _, err := clientCfg.Namespace(); err != nil {
		return "", err
	} else {
		return namespace, nil
	}
}
