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

package policy

import (
	"context"
	"crypto"
	"testing"

	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	cosignSig "github.com/sigstore/cosign/pkg/signature"
	sigstoreSig "github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
)

func TestWithRekorUrl(t *testing.T) {
	cases := []struct {
		name        string
		oldRekorUrl string
		newRekorUrl string
		changed     bool
	}{
		{
			name:        "update with new value",
			oldRekorUrl: "https://old.rekor/api",
			newRekorUrl: "https://new.rekor/api",
			changed:     true,
		},
		{
			name:        "ignore same value",
			oldRekorUrl: "https://rekor/api",
			newRekorUrl: "https://rekor/api",
			changed:     false,
		},
		{
			name:        "ignore empty string",
			oldRekorUrl: "https://rekor/api",
			newRekorUrl: "",
			changed:     false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oldPolicy := &ecc.EnterpriseContractPolicy{
				Spec: ecc.EnterpriseContractPolicySpec{
					RekorUrl: c.oldRekorUrl,
				},
			}

			newPolicy := WithRekorUrl(oldPolicy, c.newRekorUrl)

			// Verify original policy has not changed
			assert.Equal(t, c.oldRekorUrl, oldPolicy.Spec.RekorUrl)

			if c.changed {
				assert.Equal(t, c.newRekorUrl, newPolicy.Spec.RekorUrl)
			} else {
				assert.Same(t, oldPolicy, newPolicy)
			}
		})
	}
}

func TestWithPublicKey(t *testing.T) {
	cases := []struct {
		name         string
		oldPublicKey string
		newPublicKey string
		changed      bool
	}{
		{
			name:         "update with new value",
			oldPublicKey: "k8s://test/old",
			newPublicKey: "k8s://test/new",
			changed:      true,
		},
		{
			name:         "ignore same value",
			oldPublicKey: "k8s://test/cosign-public-secret",
			newPublicKey: "k8s://test/cosign-public-secret",
			changed:      false,
		},
		{
			name:         "ignore empty string",
			oldPublicKey: "k8s://test/cosign-public-secret",
			newPublicKey: "",
			changed:      false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oldPolicy := &ecc.EnterpriseContractPolicy{
				Spec: ecc.EnterpriseContractPolicySpec{
					PublicKey: c.oldPublicKey,
				},
			}

			newPolicy := WithPublicKey(oldPolicy, c.newPublicKey)

			// Verify original policy has not changed
			assert.Equal(t, c.oldPublicKey, oldPolicy.Spec.PublicKey)

			if c.changed {
				assert.Equal(t, c.newPublicKey, newPolicy.Spec.PublicKey)
			} else {
				assert.Same(t, oldPolicy, newPolicy)
			}
		})
	}
}

func TestCheckOpts(t *testing.T) {
	testRekorUrl := "https://example.com/api"
	testPublicKey := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt/WF76OOR/jS8+XnrlUeOw6hk01n
CTeemlLBj+GVwnrnTgS1ow2jxgOgNFs0ADh2UfqHQqxeXFmphmsiAxtOxA==
-----END PUBLIC KEY-----
`
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
			publicKeyFromKeyRef = func(ctx context.Context, keyRef string) (sigstoreSig.Verifier, error) {
				return cosignSig.LoadPublicKeyRaw([]byte(c.remotePublicKey), crypto.SHA256)
			}
			policy := WithRekorUrl(&ecc.EnterpriseContractPolicy{}, c.rekorUrl)
			policy = WithPublicKey(policy, c.publicKey)
			opts, err := CheckOpts(context.Background(), policy)
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
