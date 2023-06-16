// Copyright 2023 Red Hat, Inc.
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

package signature

import (
	"context"
	"encoding/hex"
	"encoding/pem"

	"github.com/google/go-containerregistry/pkg/name"
	confOutput "github.com/open-policy-agent/conftest/output"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	log "github.com/sirupsen/logrus"

	"github.com/enterprise-contract/ec-cli/internal/certificate"
	"github.com/enterprise-contract/ec-cli/internal/output"
	"github.com/enterprise-contract/ec-cli/internal/sigstore"
	"github.com/enterprise-contract/ec-cli/internal/validator"
)

const SignatureValidatorName = "image-signature"

const (
	code           = "builtin.image.signature_check"
	title          = "Image signature check passed"
	successMessage = "Pass"
)

type SignatureValidator struct {
	opts validator.Options
}

func (v SignatureValidator) Validate(ctx context.Context, image name.Reference) *validator.ImageResult {
	status := confOutput.Result{
		Metadata: map[string]interface{}{
			"code":  code,
			"title": title,
		},
	}

	result := &validator.ImageResult{}
	sigs, err := v.validateImage(ctx, image)
	if err == nil {
		status.Message = successMessage
		result.Successes = append(result.Successes, status)
		log.Debug(title)
	} else {
		status.Message = sigstore.WrapCosignErrorMessage(err, "signature", v.opts.Policy)
		result.Violations = append(result.Violations, status)
		log.Debug(status.Message)
	}
	result.Signatures = sigs

	return result
}

func (v SignatureValidator) validateImage(ctx context.Context, image name.Reference) ([]output.EntitySignature, error) {
	// TODO: Set the ClaimVerifier on a shallow *copy* of CheckOpts to avoid unexpected side-effects
	// TODO: Policy.CheckOpts should return a copy of CheckOpts
	checkOpts, err := v.opts.Policy.CheckOpts()
	if err != nil {
		return nil, err
	}
	checkOpts.ClaimVerifier = cosign.SimpleClaimVerifier
	signatures, _, err := sigstore.NewClient(ctx).VerifyImageSignatures(ctx, image, checkOpts)
	if err != nil {
		return nil, err
	}

	entitySignatures := make([]output.EntitySignature, 0, len(signatures))

	for _, s := range signatures {
		sig, err := s.Base64Signature()
		if err != nil {
			return nil, err
		}

		es := output.EntitySignature{
			Signature: sig,
			Metadata:  map[string]string{},
		}

		cert, err := s.Cert()
		if err != nil {
			return nil, err
		}
		if cert != nil {
			es.Certificate = string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}))
			es.KeyID = hex.EncodeToString(cert.SubjectKeyId)

			if err := certificate.AddCertificateMetadataTo(&es.Metadata, cert); err != nil {
				return nil, err
			}
		}

		chain, err := s.Chain()
		if err != nil {
			return nil, err
		}
		for _, c := range chain {
			es.Chain = append(es.Chain, string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: c.Raw,
			})))
		}

		entitySignatures = append(entitySignatures, es)
	}

	return entitySignatures, nil
}

func init() {
	v := func(opts validator.Options) validator.ImageValidator {
		return SignatureValidator{opts: opts}
	}
	if err := validator.RegisterImageValidator(SignatureValidatorName, v); err != nil {
		panic(err)
	}
}
