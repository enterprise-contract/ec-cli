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
	"errors"
	"strings"

	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	cosignSig "github.com/sigstore/cosign/pkg/signature"
	sigstoreSig "github.com/sigstore/sigstore/pkg/signature"
	log "github.com/sirupsen/logrus"
)

// WithRekorUrl returns a new instance of EnterpriseContractPolicy if an update
// to its rekorUrl is needed. Otherwise, the same instance is returned.
func WithRekorUrl(policy *ecc.EnterpriseContractPolicy, rekorUrl string) *ecc.EnterpriseContractPolicy {
	if rekorUrl != "" && rekorUrl != policy.Spec.RekorUrl {
		newPolicy := policy.DeepCopy()
		newPolicy.Spec.RekorUrl = rekorUrl
		log.Debugf("Updated rekor URL in policy to %q", rekorUrl)
		return newPolicy
	} else {
		return policy
	}
}

// WithPublicKey returns a new instance of EnterpriseContractPolicy if an update
// to its publicKey is needed. Otherwise, the same instance is returned.
func WithPublicKey(policy *ecc.EnterpriseContractPolicy, publicKey string) *ecc.EnterpriseContractPolicy {
	if publicKey != "" && publicKey != policy.Spec.PublicKey {
		newPolicy := policy.DeepCopy()
		newPolicy.Spec.PublicKey = publicKey
		log.Debugf("Updated public key in policy to %q", publicKey)
		return newPolicy
	} else {
		return policy
	}
}

// CheckOpts returns an instance based on attributes of the EnterpriseContractPolicy.
func CheckOpts(ctx context.Context, policy *ecc.EnterpriseContractPolicy) (*cosign.CheckOpts, error) {
	checkOpts := cosign.CheckOpts{}

	verifier, err := signatureVerifier(ctx, policy)
	if err != nil {
		return nil, err
	}
	checkOpts.SigVerifier = verifier

	rekorUrl := policy.Spec.RekorUrl
	if rekorUrl != "" {
		rekorClient, err := rekor.NewClient(rekorUrl)
		if err != nil {
			log.Debugf("Problem creating a rekor client using url %q", rekorUrl)
			return nil, err
		}

		checkOpts.RekorClient = rekorClient
		log.Debug("Rekor client created")
	}
	return &checkOpts, nil
}

// publicKeyFromKeyRef facilitates with unit testing.
var publicKeyFromKeyRef = cosignSig.PublicKeyFromKeyRef

// signatureVerifier creates a new instance based on the PublicKey from the
// EnterpriseContractPolicy.
func signatureVerifier(ctx context.Context, policy *ecc.EnterpriseContractPolicy) (sigstoreSig.Verifier, error) {
	publicKey := policy.Spec.PublicKey
	if publicKey == "" {
		return nil, errors.New("public key cannot be empty")
	}

	if strings.Contains(publicKey, "-----BEGIN PUBLIC KEY-----") {
		verifier, err := cosignSig.LoadPublicKeyRaw([]byte(publicKey), crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return verifier, nil
	}

	verifier, err := publicKeyFromKeyRef(ctx, publicKey)
	if err != nil {
		// log.Debugf("Problem creating signature verifier using public key %q", publicKey)
		return nil, err
	}
	return verifier, nil
}
