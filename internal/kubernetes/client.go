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

	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client interface {
	FetchEnterpriseContractPolicy(ctx context.Context, ref string) (*ecc.EnterpriseContractPolicy, error)
}

type kubernetesClient struct {
	client client.Client
}

// NewClient constructs a new kubernetes with the default "live" client
func NewClient() (Client, error) {
	clnt, err := createControllerRuntimeClient()
	if err != nil {
		log.Debug("Failed to create k8s client!")
		return nil, err
	}

	return &kubernetesClient{
		client: clnt,
	}, nil
}

func createControllerRuntimeClient() (client.Client, error) {
	scheme := runtime.NewScheme()
	err := ecc.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}

	kubeconfig, err := controllerruntime.GetConfig()
	if err != nil {
		return nil, err
	}

	clnt, err := client.New(kubeconfig, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}

	return clnt, err
}

// FetchEnterpriseContractPolicy gets the Enterprise Contract Policy from the given
// reference in a Kubernetes cluster.
//
// The reference is expected to be in the format [<namespace>/]<name>. If it does not contain
// a namespace, the current namespace is used.
func (k *kubernetesClient) FetchEnterpriseContractPolicy(ctx context.Context, ref string) (*ecc.EnterpriseContractPolicy, error) {
	if len(ref) == 0 {
		return nil, errors.New("policy reference cannot be empty")
	}
	log.Debugf("Raw policy reference: %q", ref)

	name, err := NamespacedName(ref)
	if err != nil {
		return nil, err
	}
	log.Debugf("Parsed policy reference: %v", name)
	if name.Namespace == "" {
		return nil, errors.New("unable to determine namespace for policy")
	}

	policy := &ecc.EnterpriseContractPolicy{}
	if err := k.client.Get(ctx, *name, policy); err != nil {
		log.Debugf("Failed to fetch the policy from cluster: %s", err)
		return nil, err
	}
	log.Debugf("Policy successfully fetched from cluster: %#v", policy)

	return policy, nil
}
