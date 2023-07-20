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

//go:build unit

package policy

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cosignSig "github.com/sigstore/cosign/v2/pkg/signature"
	sigstoreSig "github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/yaml"

	"github.com/enterprise-contract/ec-cli/internal/kubernetes"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

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
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "simple YAML inline",
			policyRef: toYAML(&ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "JSON inline with public key overwrite",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: "ignored"}),
			publicKey: utils.TestPublicKey,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "YAML inline with public key overwrite",
			policyRef: toYAML(&ecc.EnterpriseContractPolicySpec{PublicKey: "ignored"}),
			publicKey: utils.TestPublicKey,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "JSON inline with rekor URL",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "YAML inline with rekor URL",
			policyRef: toYAML(&ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL}),
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "JSON inline with rekor URL overwrite",
			policyRef: toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey, RekorUrl: "ignored"}),
			rekorUrl:  utils.TestRekorURL,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "YAML inline with rekor URL overwrite",
			policyRef: toYAML(&ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey, RekorUrl: "ignored"}),
			rekorUrl:  utils.TestRekorURL,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:        "simple k8sPath",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey},
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:        "k8sPath with public key overwrite",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: "ignored"},
			publicKey:   utils.TestPublicKey,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:        "k8sPath with rekor URL",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL},
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:        "k8sPath with rekor overwrite",
			policyRef:   "ec-policy",
			k8sResource: &ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey},
			rekorUrl:    utils.TestRekorURL,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey, RekorUrl: utils.TestRekorURL}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
		{
			name:      "default empty policy",
			publicKey: utils.TestPublicKey,
			expected: &policy{EnterpriseContractPolicySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: utils.TestPublicKey}, effectiveTime: &timeNow, choosenTime: timeNowStr},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			// Setup an fake client to simulate external connections.
			if c.k8sResource != nil {
				ctx = kubernetes.WithClient(ctx, &FakeKubernetesClient{Policy: *c.k8sResource})
			}
			utils.SetTestRekorPublicKey(t)
			got, err := NewPolicy(ctx, c.policyRef, c.rekorUrl, c.publicKey, timeNowStr, cosign.Identity{})
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
			got, err := NewPolicy(ctx, c.policyRef, "", "", "", cosign.Identity{})
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
		setExperimental bool
		identity        cosign.Identity
		expectKeyless   bool
		err             string
	}{
		{
			name:      "create rekor client",
			rekorUrl:  utils.TestRekorURL,
			publicKey: utils.TestPublicKey,
		},
		{
			name:      "inline public key",
			publicKey: utils.TestPublicKey,
		},
		{
			name:            "in-cluster public key",
			publicKey:       "k8s://test/cosign-public-key",
			remotePublicKey: utils.TestPublicKey,
		},
		{
			name:      "with rekor public key",
			rekorUrl:  utils.TestRekorURL,
			publicKey: utils.TestPublicKey,
		},
		{
			name: "missing public key",
			err:  "policy must provide a public key",
		},
		{
			name:            "keyless",
			rekorUrl:        utils.TestRekorURL,
			setExperimental: true,
			expectKeyless:   true,
			identity: cosign.Identity{
				Issuer:  "my-issuer",
				Subject: "my-subject",
			},
		},
		{
			name:            "keyless without rekor",
			setExperimental: true,
			expectKeyless:   true,
			identity: cosign.Identity{
				Issuer:  "my-issuer",
				Subject: "my-subject",
			},
		},
		{
			name:            "keyless with regexp issuer",
			rekorUrl:        utils.TestRekorURL,
			setExperimental: true,
			expectKeyless:   true,
			identity: cosign.Identity{
				IssuerRegExp: "my-issuer-regexp",
				Subject:      "my-subject",
			},
		},
		{
			name:            "keyless with regexp subject",
			rekorUrl:        utils.TestRekorURL,
			setExperimental: true,
			expectKeyless:   true,
			identity: cosign.Identity{
				Issuer:        "my-issuer",
				SubjectRegExp: "my-subject-regexp",
			},
		},
		{
			name:            "keyless with regexp issuer and subject",
			rekorUrl:        utils.TestRekorURL,
			setExperimental: true,
			expectKeyless:   true,
			identity: cosign.Identity{
				IssuerRegExp:  "my-issuer-regexp",
				SubjectRegExp: "my-subject-regexp",
			},
		},
		{
			name:            "prioritize public key worklow",
			rekorUrl:        utils.TestRekorURL,
			publicKey:       utils.TestPublicKey,
			setExperimental: true,
			expectKeyless:   false,
			identity: cosign.Identity{
				Issuer:  "my-issuer",
				Subject: "my-subject",
			},
		},
		{
			name:            "keyless missing issuer",
			setExperimental: true,
			err:             "certificate OIDC issuer must be provided for keyless workflow",
			identity: cosign.Identity{
				Subject: "my-subject",
			},
		},
		{
			name:            "keyless missing subject",
			setExperimental: true,
			err:             "certificate identity must be provided for keyless workflow",
			identity: cosign.Identity{
				Issuer: "my-issuer",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			ctx = withSignatureClient(ctx, &FakeCosignClient{publicKey: c.remotePublicKey})
			utils.SetTestRekorPublicKey(t)
			utils.SetTestFulcioRoots(t)
			utils.SetTestCTLogPublicKey(t)

			if c.setExperimental {
				t.Setenv("EC_EXPERIMENTAL", "1")
			}

			p, err := NewPolicy(ctx, "", c.rekorUrl, c.publicKey, Now, c.identity)
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
				assert.False(t, opts.IgnoreTlog)
			} else {
				assert.Nil(t, opts.RekorClient)
				assert.True(t, opts.IgnoreTlog)
			}

			if c.rekorUrl != "" {
				assert.NotNil(t, opts.RekorPubKeys)
				_, present := opts.RekorPubKeys.Keys[utils.TestRekorURLLogID]
				assert.True(t, present, "Expecting specific log id based on the provided public key")
			} else {
				assert.Nil(t, opts.RekorPubKeys)
			}

			if c.expectKeyless {
				assert.Empty(t, opts.SigVerifier)
				assert.Equal(t, opts.Identities, []cosign.Identity{c.identity})
				assert.NotEmpty(t, opts.RootCerts)
				assert.NotEmpty(t, opts.IntermediateCerts)
				assert.NotEmpty(t, opts.CTLogPubKeys)
			} else {
				assert.NotEmpty(t, opts.SigVerifier)
				assert.Empty(t, opts.Identities)
				assert.Empty(t, opts.RootCerts)
				assert.Empty(t, opts.IntermediateCerts)
				assert.Empty(t, opts.CTLogPubKeys)
			}
		})
	}
}

func TestPublicKeyPEM(t *testing.T) {
	cases := []struct {
		name              string
		remotePublicKey   string
		setExperimental   bool
		newPolicy         func(context.Context) (Policy, error)
		expectedPublicKey string
		err               string
	}{
		{
			name: "public key",
			newPolicy: func(ctx context.Context) (Policy, error) {
				return NewPolicy(ctx, "", "", utils.TestPublicKey, Now, cosign.Identity{})
			},
			expectedPublicKey: utils.TestPublicKey,
		},
		{
			name: "checkOpts is nil",
			newPolicy: func(ctx context.Context) (Policy, error) {
				return NewInertPolicy(ctx, "")
			},
			err: "no check options or sig verifier configured",
		},
		{
			name:            "keyless",
			setExperimental: true,
			newPolicy: func(ctx context.Context) (Policy, error) {
				return NewPolicy(ctx, "", "", "", Now, cosign.Identity{
					Subject: "my-subject", Issuer: "my-issuer"})
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			utils.SetTestFulcioRoots(t)
			utils.SetTestCTLogPublicKey(t)

			if c.setExperimental {
				t.Setenv("EC_EXPERIMENTAL", "1")
			}

			p, err := c.newPolicy(ctx)
			assert.NoError(t, err)

			publicKeyPEM, err := p.PublicKeyPEM()
			if c.err != "" {
				assert.Empty(t, p)
				assert.ErrorContains(t, err, c.err)
				return
			}
			assert.NoError(t, err)

			assert.Equal(t,
				strings.TrimSpace(c.expectedPublicKey),
				strings.TrimSpace(string(publicKeyPEM)))
		})
	}
}

func TestIdentity(t *testing.T) {
	cases := []struct {
		name             string
		newPolicy        func(context.Context) (Policy, error)
		expectedIdentity cosign.Identity
		err              string
	}{
		{
			name: "simple",
			newPolicy: func(ctx context.Context) (Policy, error) {
				return NewPolicy(ctx, "", "", "", Now, cosign.Identity{
					Subject: "my-subject", Issuer: "my-issuer",
				})
			},
			expectedIdentity: cosign.Identity{Subject: "my-subject", Issuer: "my-issuer"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			utils.SetTestFulcioRoots(t)
			utils.SetTestCTLogPublicKey(t)

			t.Setenv("EC_EXPERIMENTAL", "1")

			p, err := c.newPolicy(ctx)
			assert.NoError(t, err)

			assert.Equal(t, p.Identity(), c.expectedIdentity)
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
