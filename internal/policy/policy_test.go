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

package policy

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	cosignSig "github.com/sigstore/cosign/pkg/signature"
	sigstoreSig "github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/kubernetes"
)

const testPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt/WF76OOR/jS8+XnrlUeOw6hk01n
CTeemlLBj+GVwnrnTgS1ow2jxgOgNFs0ADh2UfqHQqxeXFmphmsiAxtOxA==
-----END PUBLIC KEY-----
`

const testRekorUrl = "https://example.com/api"

type FakeKubernetesClient struct {
	policy     ecc.EnterpriseContractPolicySpec
	fetchError bool
}

func (c *FakeKubernetesClient) FetchEnterpriseContractPolicy(ctx context.Context, ref string) (*ecc.EnterpriseContractPolicy, error) {
	if c.fetchError {
		return nil, errors.New("no fetching for you")
	}
	return &ecc.EnterpriseContractPolicy{Spec: c.policy}, nil
}

func TestNewPolicy(t *testing.T) {
	cases := []struct {
		name        string
		policyRef   string
		k8sResource *ecc.EnterpriseContractPolicySpec
		rekorUrl    string
		publicKey   string
		expected    *ecc.EnterpriseContractPolicySpec
	}{
		{
			name:      "simple inline",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey}),
			expected:  &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey},
		},
		{
			name:      "inline with public key overwrite",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: "ignored"}),
			publicKey: testPublicKey,
			expected:  &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey},
		},
		{
			name:      "inline with rekor URL",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey, RekorUrl: testRekorUrl}),
			expected:  &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey, RekorUrl: testRekorUrl},
		},
		{
			name:      "inline with rekor URL overwrite",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey, RekorUrl: "ignored"}),
			rekorUrl:  testRekorUrl,
			expected:  &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey, RekorUrl: testRekorUrl},
		},
		{
			name:        "simple k8sPath",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey},
			expected:    &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey},
		},
		{
			name:        "k8sPath with public key overwrite",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: "ignored"},
			publicKey:   testPublicKey,
			expected:    &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey},
		},
		{
			name:        "k8sPath with rekor URL",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey, RekorUrl: testRekorUrl},
			expected:    &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey, RekorUrl: testRekorUrl},
		},
		{
			name:        "k8sPath with rekor overwrite",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey},
			rekorUrl:    testRekorUrl,
			expected:    &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey, RekorUrl: testRekorUrl},
		},
		{
			name:      "default empty policy",
			publicKey: testPublicKey,
			expected:  &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			// Setup an fake client to simulate external connections.
			if c.k8sResource != nil {
				ctx = kubernetes.WithClient(ctx, &FakeKubernetesClient{policy: *c.k8sResource})
			}
			got, err := NewPolicy(ctx, c.policyRef, c.rekorUrl, c.publicKey)
			assert.NoError(t, err)
			assert.Equal(t, c.expected, got)
		})
	}
}

func TestNewPolicyFailures(t *testing.T) {
	cases := []struct {
		name       string
		errorCause string
		policyRef  string
		k8sError   bool
	}{
		{
			name:       "public key is required",
			errorCause: "policy must provide a public key",
		},
		{
			name:       "invalid inline JSON",
			policyRef:  "{invalid json}",
			errorCause: "unable to parse",
		},
		{
			name:       "unable to fetch resource",
			policyRef:  "ec-policy",
			k8sError:   true,
			errorCause: "unable to fetch",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			ctx = kubernetes.WithClient(ctx, &FakeKubernetesClient{fetchError: c.k8sError})
			got, err := NewPolicy(ctx, c.policyRef, "", "")
			assert.Nil(t, got)
			assert.ErrorContains(t, err, c.errorCause)
		})
	}
}

type FakeCosignClient struct {
	publicKey string
}

func (c *FakeCosignClient) publicKeyFromKeyRef(context.Context, string) (sigstoreSig.Verifier, error) {
	return cosignSig.LoadPublicKeyRaw([]byte(c.publicKey), crypto.SHA256)
}

func TestCheckOpts(t *testing.T) {
	cases := []struct {
		name            string
		rekorUrl        string
		publicKey       string
		remotePublicKey string
		err             string
	}{
		{
			name:      "create rekor client",
			rekorUrl:  testRekorUrl,
			publicKey: testPublicKey,
		},
		{
			name:      "public key is required",
			publicKey: "",
			err:       "public key cannot be empty",
		},
		{
			name:      "inline public key",
			publicKey: testPublicKey,
		},
		{
			name:            "in-cluster public key",
			publicKey:       "k8s://test/cosign-public-key",
			remotePublicKey: testPublicKey,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			ctx = withSignatureClient(ctx, &FakeCosignClient{publicKey: c.remotePublicKey})
			policy := &ecc.EnterpriseContractPolicySpec{
				PublicKey: c.publicKey,
				RekorUrl:  c.rekorUrl,
			}
			opts, err := CheckOpts(ctx, policy)
			if c.err != "" {
				assert.Empty(t, opts)
				assert.ErrorContains(t, err, c.err)
				return
			}
			assert.NoError(t, err)

			if c.rekorUrl != "" {
				assert.NotNil(t, opts.RekorClient)
			} else {
				assert.Nil(t, opts.RekorClient)
			}

			assert.NotEmpty(t, opts.SigVerifier)
		})
	}
}

func toJson(policy *ecc.EnterpriseContractPolicySpec) string {
	newInline, err := json.Marshal(policy)
	if err != nil {
		panic(fmt.Errorf("invalid JSON: %w", err))
	}
	return string(newInline)
}
