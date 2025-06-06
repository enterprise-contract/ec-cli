// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/enterprise-contract/ec-cli/internal/applicationsnapshot"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
)

// FS is the filesystem used for all file operations in this package. It defaults to the OS filesystem but can be replaced for testing.
var FS afero.Fs = afero.NewOsFs()

// Predicate defines the structure of the per-image VSA predicate.
type Predicate struct {
	ImageRef         string                 `json:"imageRef"`
	ValidationResult string                 `json:"validationResult"` // "passed" or "failed"
	Timestamp        string                 `json:"timestamp"`
	Verifier         string                 `json:"verifier"`
	PolicySource     string                 `json:"policySource"`
	Component        map[string]interface{} `json:"component"`
	RuleResults      []evaluator.Result     `json:"ruleResults"`
}

// Options for VSA generation
// Extend as needed for more context
// (e.g., output dir, signing key, etc.)
type Options struct {
	OutputDir      string
	SigningKeyPath string
}

// GeneratePredicate creates a Predicate for a validated image/component.
func GeneratePredicate(ctx context.Context, report applicationsnapshot.Report, component applicationsnapshot.Component, opts Options) (*Predicate, error) {
	log.Infof("Generating VSA predicate for image: %s", component.ContainerImage)

	// Compose the component info as a map
	componentInfo := map[string]interface{}{
		"name":           component.Name,
		"containerImage": component.ContainerImage,
		"source":         component.Source,
	}

	// Compose rule results: combine violations, warnings, and successes
	ruleResults := make([]evaluator.Result, 0, len(component.Violations)+len(component.Warnings)+len(component.Successes))
	ruleResults = append(ruleResults, component.Violations...)
	ruleResults = append(ruleResults, component.Warnings...)
	ruleResults = append(ruleResults, component.Successes...)

	validationResult := "failed"
	if component.Success {
		validationResult = "passed"
	}

	policySource := ""
	if report.Policy.PublicKey != "" {
		policySource = report.Policy.Name
	}

	return &Predicate{
		ImageRef:         component.ContainerImage,
		ValidationResult: validationResult,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Verifier:         "Conforma",
		PolicySource:     policySource,
		Component:        componentInfo,
		RuleResults:      ruleResults,
	}, nil
}

// WriteVSA writes the Predicate as a JSON file to the given path.
func WriteVSA(predicate *Predicate, path string) error {
	log.Infof("Writing VSA to %s", path)
	data, err := json.MarshalIndent(predicate, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal VSA predicate: %w", err)
	}
	if err := FS.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create VSA output directory: %w", err)
	}
	if err := afero.WriteFile(FS, path, data, 0600); err != nil {
		log.Errorf("Failed to write VSA file: %v", err)
		return fmt.Errorf("failed to write VSA file: %w", err)
	}
	return nil
}

// For testability, allow dependency injection of key loader and sign function
// These types match the cosign APIs

type PrivateKeyLoader func(key []byte, pass []byte) (signature.SignerVerifier, error)
type AttestationSigner func(ctx context.Context, signer signature.SignerVerifier, ref name.Reference, att oci.Signature, opts *cosign.CheckOpts) (name.Digest, error)

// SignVSAOptions allows injection for testing
// If nil, defaults to production cosign implementations
type SignVSAOptions struct {
	KeyLoader PrivateKeyLoader
	SignFunc  AttestationSigner
}

// AttestationUploader is a function that uploads an attestation and returns a result string or error
// This allows pluggable upload logic (OCI, Rekor, None, or custom)
type AttestationUploader func(ctx context.Context, att oci.Signature, location string) (string, error)

// Built-in uploaders
func OCIUploader(ctx context.Context, att oci.Signature, location string) (string, error) {
	log.Infof("Uploading VSA attestation to OCI registry for %s", location)
	// TODO: Implement OCI upload logic here
	return "", fmt.Errorf("OCI upload not implemented")
}

func RekorUploader(ctx context.Context, att oci.Signature, location string) (string, error) {
	log.Infof("Uploading VSA attestation to Rekor for %s", location)
	// TODO: Implement Rekor upload logic here
	return "", fmt.Errorf("rekor upload not implemented")
}

func NoopUploader(ctx context.Context, att oci.Signature, location string) (string, error) {
	log.Infof("Upload type is 'none'; skipping upload for %s", location)
	return "", nil
}

// SignVSA signs the VSA file and returns an oci.Signature (does not upload)
func SignVSA(ctx context.Context, vsaPath, keyPath, imageRef string, opts ...SignVSAOptions) (oci.Signature, error) {
	log.Infof("Signing VSA for image: %s", imageRef)
	vsaData, err := afero.ReadFile(FS, vsaPath)
	if err != nil {
		log.Errorf("Failed to read VSA file: %v", err)
		return nil, fmt.Errorf("failed to read VSA file: %w", err)
	}
	// TODO: Actually sign the attestation using cosign APIs. For now, just create the attestation object.
	att, err := static.NewAttestation(vsaData)
	if err != nil {
		log.Errorf("Failed to create attestation: %v", err)
		return nil, fmt.Errorf("failed to create attestation: %w", err)
	}
	log.Infof("VSA attestation (unsigned) created for %s", imageRef)
	return att, nil
}
