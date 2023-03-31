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
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	cosignSig "github.com/sigstore/cosign/v2/pkg/signature"
	sigstoreSig "github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/yaml"

	"github.com/enterprise-contract/ec-cli/internal/kubernetes"
)

const testPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt/WF76OOR/jS8+XnrlUeOw6hk01n
CTeemlLBj+GVwnrnTgS1ow2jxgOgNFs0ADh2UfqHQqxeXFmphmsiAxtOxA==
-----END PUBLIC KEY-----
`

const testRekorUrl = "https://example.com/api"
const testRekorURLLogID = "5c88613c1a35d9fbf61144a6762502d594d9433c065af8d0b375f4bda16464b8"

func TestNewPolicy(t *testing.T) {
	timeNowStr := "2022-11-23T16:30:00Z"
	timeNow, err := time.Parse(time.RFC3339, timeNowStr)
	assert.NoError(t, err)

	cases := []struct {
		name        string
		policyRef   string
		k8sResource *ecc.EnterpriseContractPolicySpec
		rekorUrl    string
		publicKey   string
		expected    *policy
	}{
		{
			name:      "simple JSON inline",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: testPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "simple YAML inline",
			policyRef: toYAML(&ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: testPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "JSON inline with public key overwrite",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: "ignored"}),
			publicKey: testPublicKey,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: testPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "YAML inline with public key overwrite",
			policyRef: toYAML(&ecc.EnterpriseContractPolicySpec{PublicKey: "ignored"}),
			publicKey: testPublicKey,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: testPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "JSON inline with rekor URL",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey, RekorUrl: testRekorUrl}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: testPublicKey, RekorUrl: testRekorUrl}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "YAML inline with rekor URL",
			policyRef: toYAML(&ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey, RekorUrl: testRekorUrl}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: testPublicKey, RekorUrl: testRekorUrl}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "JSON inline with rekor URL overwrite",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey, RekorUrl: "ignored"}),
			rekorUrl:  testRekorUrl,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: testPublicKey, RekorUrl: testRekorUrl}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "YAML inline with rekor URL overwrite",
			policyRef: toYAML(&ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey, RekorUrl: "ignored"}),
			rekorUrl:  testRekorUrl,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: testPublicKey, RekorUrl: testRekorUrl}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:        "simple k8sPath",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey},
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: testPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:        "k8sPath with public key overwrite",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: "ignored"},
			publicKey:   testPublicKey,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: testPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:        "k8sPath with rekor URL",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey, RekorUrl: testRekorUrl},
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: testPublicKey, RekorUrl: testRekorUrl}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:        "k8sPath with rekor overwrite",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: testPublicKey},
			rekorUrl:    testRekorUrl,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: testPublicKey, RekorUrl: testRekorUrl}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "default empty policy",
			publicKey: testPublicKey,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: testPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			// Setup an fake client to simulate external connections.
			if c.k8sResource != nil {
				ctx = kubernetes.WithClient(ctx, &FakeKubernetesClient{Policy: *c.k8sResource})
			}
			setupRekorPublicKey(t)
			got, err := NewPolicy(ctx, c.policyRef, c.rekorUrl, c.publicKey, timeNowStr)
			assert.NoError(t, err)
			// CheckOpts is more thoroughly checked in TestCheckOpts.
			got.(*policy).checkOpts = nil
			assert.Equal(t, c.expected.EffectiveTime(), got.EffectiveTime())

			c.expected.effectiveTime = nil
			got.(*policy).effectiveTime = nil

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
			policyRef:  `{"invalid": "json""}`,
			errorCause: "unable to parse",
		},
		{
			name: "invalid inline YAML",
			policyRef: hd.Doc(`
				---
				invalid: yaml
				  spam:
				`),
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
			ctx = kubernetes.WithClient(ctx, &FakeKubernetesClient{FetchError: c.k8sError})
			got, err := NewPolicy(ctx, c.policyRef, "", "", "")
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
			name:      "inline public key",
			publicKey: testPublicKey,
		},
		{
			name:            "in-cluster public key",
			publicKey:       "k8s://test/cosign-public-key",
			remotePublicKey: testPublicKey,
		},
		{
			name:      "with rekor public key",
			rekorUrl:  testRekorUrl,
			publicKey: testPublicKey,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			ctx = withSignatureClient(ctx, &FakeCosignClient{publicKey: c.remotePublicKey})
			setupRekorPublicKey(t)
			p, err := NewPolicy(ctx, "", c.rekorUrl, c.publicKey, Now)
			if c.err != "" {
				assert.Empty(t, p)
				assert.ErrorContains(t, err, c.err)
				return
			}
			assert.NoError(t, err)

			opts, err := p.CheckOpts()
			assert.NoError(t, err)

			if c.rekorUrl != "" {
				assert.NotNil(t, opts.RekorClient)
			} else {
				assert.Nil(t, opts.RekorClient)
			}

			if c.rekorUrl != "" {
				assert.NotNil(t, opts.RekorPubKeys)
				_, present := opts.RekorPubKeys.Keys[testRekorURLLogID]
				assert.True(t, present, "Expecting specific log id based on the provided public key")
			} else {
				assert.Nil(t, opts.RekorPubKeys)
			}

			assert.NotEmpty(t, opts.SigVerifier)
		})
	}
}

func TestParseEffectiveTime(t *testing.T) {
	_, err := parseEffectiveTime("")
	assert.ErrorContains(t, err, "PO001")

	effective, err := parseEffectiveTime(Now)
	assert.NoError(t, err)
	assert.Equal(t, time.UTC, effective.Location())

	then := now
	t.Cleanup(func() {
		now = then
	})

	epoch := time.Unix(0, 0).UTC()
	now = func() time.Time { return epoch }

	effective, err = parseEffectiveTime(Now)
	assert.NoError(t, err)
	assert.NotNil(t, effective)
	assert.Equal(t, epoch, *effective)

	effective, err = parseEffectiveTime("2001-02-03T04:05:06+07:00")
	assert.NoError(t, err)
	assert.NotNil(t, effective)
	assert.Equal(t, time.Date(2001, 2, 2, 21, 5, 6, 0, time.UTC), *effective)

	effective, err = parseEffectiveTime("2001-02-03")
	assert.NoError(t, err)
	assert.NotNil(t, effective)
	assert.Equal(t, time.Date(2001, 2, 3, 0, 0, 0, 0, time.UTC), *effective)

	effective, err = parseEffectiveTime("attestation")
	assert.NoError(t, err)
	assert.Nil(t, effective)
}

func TestEffectiveTimeNowNoMutation(t *testing.T) {
	then := now
	t.Cleanup(func() {
		now = then
	})

	epoch := time.Unix(0, 0).UTC()
	now = func() time.Time { return epoch }

	p, err := NewOfflinePolicy(context.Background(), Now)
	assert.NoError(t, err)

	assert.Equal(t, epoch, p.EffectiveTime())

	p.AttestationTime(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))

	assert.Equal(t, epoch, p.EffectiveTime())
}

func TestEffectiveTimeGivenNoMutation(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()

	p, err := NewOfflinePolicy(context.Background(), epoch.Format(time.RFC3339))
	assert.NoError(t, err)

	assert.Equal(t, epoch, p.EffectiveTime())

	p.AttestationTime(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))

	assert.Equal(t, epoch, p.EffectiveTime())
}

func TestEffectiveTimeAttestationAllowMutation(t *testing.T) {
	then := now
	t.Cleanup(func() {
		now = then
	})

	epoch := time.Unix(0, 0).UTC()
	now = func() time.Time { return epoch }

	p, err := NewOfflinePolicy(context.Background(), AtAttestation)
	assert.NoError(t, err)

	// falling back to now, as attestation time hasn't been set
	assert.Equal(t, epoch, p.EffectiveTime())

	attestation := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	p.AttestationTime(attestation)

	assert.Equal(t, attestation, p.EffectiveTime())
}

func toJson(policy *ecc.EnterpriseContractPolicySpec) string {
	newInline, err := json.Marshal(policy)
	if err != nil {
		panic(fmt.Errorf("invalid JSON: %w", err))
	}
	return string(newInline)
}

func toYAML(policy *ecc.EnterpriseContractPolicySpec) string {
	inline, err := yaml.Marshal(policy)
	if err != nil {
		panic(fmt.Errorf("invalid YAML: %w", err))
	}
	return string(inline)
}

func setupRekorPublicKey(t *testing.T) {
	// Do not use afero.NewMemMapFs() here because the file is read by cosign
	// which does not understand the filesystem-from-context pattern
	f, err := os.Create(path.Join(t.TempDir(), "rekor.log"))
	assert.NoError(t, err)
	defer f.Close()
	_, err = f.Write([]byte(testPublicKey))
	assert.NoError(t, err)
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", f.Name())
}
