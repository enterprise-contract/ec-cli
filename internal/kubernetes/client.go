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
	"encoding/json"
	"errors"

	ecp "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client struct {
	client client.Client
}

// NewClient constructs a new kubernetes with the default "live" client
func NewClient() (*Client, error) {
	clnt, err := createControllerRuntimeClient()
	if err != nil {
		log.Debug("Failed to create k8s client!")
		return nil, err
	}

	return &Client{
		client: clnt,
	}, nil
}

func createControllerRuntimeClient() (client.Client, error) {
	scheme := runtime.NewScheme()
	err := ecp.AddToScheme(scheme)
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

// FetchEnterpriseContractPolicy gets the Enterprise Contract Policy from the given namespace in a Kubernetes cluster
func (k *Client) FetchEnterpriseContractPolicy(ctx context.Context, name types.NamespacedName) (*ecp.EnterpriseContractPolicy, error) {
	if name.Namespace == "" {
		return nil, errors.New("missing namespace")
	}

	policy := &ecp.EnterpriseContractPolicy{}

	err := k.client.Get(ctx, name, policy)
	if err != nil {
		log.Debug("Failed to get policy from cluster!")
		return nil, err
	}
	policyJson, _ := json.Marshal(policy.Spec)
	log.Debugf("Policy fetched:\n%s", policyJson)
	return policy, nil
}
