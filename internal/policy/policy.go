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
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	cosignSig "github.com/sigstore/cosign/pkg/signature"
	sigstoreSig "github.com/sigstore/sigstore/pkg/signature"
	log "github.com/sirupsen/logrus"

	"github.com/hacbs-contract/ec-cli/internal/kubernetes"
)

// NewEnterpriseContractPolicy construct and return a new instance of EnterpriseContractPolicySpec.
//
// The policyRef parameter is expected to be either a JSON-encoded instance of
// EnterpriseContractPolicySpec, or reference to the location of the EnterpriseContractPolicy
// resource in Kubernetes using the format: [namespace/]name
//
// If policyRef is blank, an empty EnterpriseContractPolicySpec is used.
//
// rekorUrl and publicKey provide a mechanism to overwrite the attributes, of same name, in the
// EnterpriseContractPolicySpec.
func NewPolicy(ctx context.Context, policyRef, rekorUrl, publicKey string) (*ecc.EnterpriseContractPolicySpec, error) {
	var policy *ecc.EnterpriseContractPolicySpec

	if policyRef == "" {
		log.Debug("Using an empty EnterpriseContractPolicy")
		// Default to an empty policy instead of returning an error because the required
		// values, e.g. PublicKey, may be provided via other means, e.g. publicKey param.
		policy = &ecc.EnterpriseContractPolicySpec{}
	} else if strings.Contains(policyRef, "{") {
		log.Debug("Read EnterpriseContractPolicy as JSON")
		if err := json.Unmarshal([]byte(policyRef), &policy); err != nil {
			log.Debugf("Problem parsing EnterpriseContractPolicy Spec from %q", policyRef)
			return nil, fmt.Errorf("unable to parse EnterpriseContractPolicy Spec: %w", err)
		}
	} else {
		log.Debug("Read EnterpriseContractPolicy as k8s resource")
		k8s, err := kubernetes.NewClient(ctx)
		if err != nil {
			log.Debug("Failed to initialize Kubernetes client")
			return nil, fmt.Errorf("cannot initialize Kubernetes client: %w", err)
		}
		log.Debug("Initialized Kubernetes client")

		ecp, err := k8s.FetchEnterpriseContractPolicy(ctx, policyRef)
		if err != nil {
			log.Debug("Failed to fetch the enterprise contract policy from the cluster!")
			return nil, fmt.Errorf("unable to fetch EnterpriseContractPolicy: %w", err)
		}
		policy = &ecp.Spec
	}

	if rekorUrl != "" && rekorUrl != policy.RekorUrl {
		policy.RekorUrl = rekorUrl
		log.Debugf("Updated rekor URL in policy to %q", rekorUrl)
	}

	if publicKey != "" && publicKey != policy.PublicKey {
		policy.PublicKey = publicKey
		log.Debugf("Updated public key in policy to %q", publicKey)
	}

	if policy.PublicKey == "" {
		return nil, errors.New("policy must provide a public key")
	}

	return policy, nil
}

// CheckOpts returns an instance based on attributes of the EnterpriseContractPolicySpec.
func CheckOpts(ctx context.Context, policy *ecc.EnterpriseContractPolicySpec) (*cosign.CheckOpts, error) {
	checkOpts := cosign.CheckOpts{}

	verifier, err := signatureVerifier(ctx, policy)
	if err != nil {
		return nil, err
	}
	checkOpts.SigVerifier = verifier

	rekorUrl := policy.RekorUrl
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

type signatureClient interface {
	publicKeyFromKeyRef(context.Context, string) (sigstoreSig.Verifier, error)
}

type cosignClient struct{}

func (c *cosignClient) publicKeyFromKeyRef(ctx context.Context, publicKey string) (sigstoreSig.Verifier, error) {
	return cosignSig.PublicKeyFromKeyRef(ctx, publicKey)
}

type contextKey string

const signatureClientContextKey contextKey = "ec.policy.signature.client"

func withSignatureClient(ctx context.Context, client signatureClient) context.Context {
	return context.WithValue(ctx, signatureClientContextKey, client)
}

func newSignatureClient(ctx context.Context) signatureClient {
	client, ok := ctx.Value(signatureClientContextKey).(signatureClient)
	if ok && client != nil {
		return client
	}

	return &cosignClient{}
}

// signatureVerifier creates a new instance based on the PublicKey from the
// EnterpriseContractPolicySpec.
func signatureVerifier(ctx context.Context, policy *ecc.EnterpriseContractPolicySpec) (sigstoreSig.Verifier, error) {
	publicKey := policy.PublicKey
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

	verifier, err := newSignatureClient(ctx).publicKeyFromKeyRef(ctx, publicKey)
	if err != nil {
		// log.Debugf("Problem creating signature verifier using public key %q", publicKey)
		return nil, err
	}
	return verifier, nil
}
