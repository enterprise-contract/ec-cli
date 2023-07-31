// Copyright The Enterprise Contract Contributors
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

package policy

import (
	"context"
	"errors"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	app "github.com/redhat-appstudio/application-api/api/v1alpha1"
)

type FakeKubernetesClient struct {
	Policy     ecc.EnterpriseContractPolicySpec
	Snapshot   app.SnapshotSpec
	FetchError bool
}

func (c *FakeKubernetesClient) FetchEnterpriseContractPolicy(ctx context.Context, ref string) (*ecc.EnterpriseContractPolicy, error) {
	if c.FetchError {
		return nil, errors.New("no fetching for you")
	}
	return &ecc.EnterpriseContractPolicy{Spec: c.Policy}, nil
}

func (c *FakeKubernetesClient) FetchSnapshot(ctx context.Context, ref string) (*app.Snapshot, error) {
	if c.FetchError {
		return nil, errors.New("no fetching for you")
	}
	return &app.Snapshot{Spec: c.Snapshot}, nil
}
