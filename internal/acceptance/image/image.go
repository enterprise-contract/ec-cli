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

// Package image handles image operations, like creating a random image, image signature
// or attestation images
package image

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/cucumber/godog"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/pkg/oci/static"
	cosigntypes "github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/hacbs-contract/ec-cli/internal/acceptance/attestation"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/crypto"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/registry"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/testenv"
)

type key int

const imageStateKey = key(0) // we store the imageState struct under this key in Context and when persisted

type imageState struct {
	Attestations map[string]string
	Images       map[string]string
	Signatures   map[string]string
}

func (g imageState) Key() any {
	return imageStateKey
}

// imageFrom returns the named image from the Context
func imageFrom(ctx context.Context, imageName string) (v1.Image, error) {
	state := testenv.FetchState[imageState](ctx)

	if state.Images[imageName] == "" {
		return nil, fmt.Errorf("can't find image info for image named %s, did you create the image beforehand", imageName)
	}

	ref, err := name.ParseReference(state.Images[imageName])
	if err != nil {
		return nil, err
	}

	return remote.Image(ref)
}

// createAndPushImageSignature for a named image in the Context creates a signature
// image, same as `cosign sign` or Tekton Chains would, of that named image and pushes it
// to the stub registry as a new tag for that image akin to how cosign and Tekton Chains
// do it
func createAndPushImageSignature(ctx context.Context, imageName string, keyName string) (context.Context, error) {
	var state *imageState
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if state.Signatures[imageName] != "" {
		// we already created the signature
		return ctx, nil
	}

	image, err := imageFrom(ctx, imageName)
	if err != nil {
		return ctx, err
	}

	digest, err := image.Digest()
	if err != nil {
		return ctx, err
	}

	// the name of the image to sign referenced by the digest
	digestImage, err := name.NewDigest(fmt.Sprintf("%s@%s", imageName, digest.String()))
	if err != nil {
		return ctx, err
	}

	signer, err := crypto.SignerWithKey(ctx, keyName)
	if err != nil {
		return ctx, err
	}

	// creates a cosign signature payload signs it and provides the raw signature
	payload, signature, err := signature.SignImage(signer, digestImage, map[string]interface{}{})
	if err != nil {
		return ctx, err
	}

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	// creates the layer with the image signature
	signatureLayer, err := static.NewSignature(payload, signatureBase64)
	if err != nil {
		return ctx, err
	}

	// creates the signature image with the correct media type and config and appends
	// the signature layer to it
	singnatureImage := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	singnatureImage = mutate.ConfigMediaType(singnatureImage, types.OCIConfigJSON)
	singnatureImage, err = mutate.Append(singnatureImage, mutate.Addendum{
		Layer: signatureLayer,
		Annotations: map[string]string{
			static.SignatureAnnotationKey: signatureBase64,
		},
	})
	if err != nil {
		return ctx, err
	}

	// the name of the image + the <hash>.sig tag
	ref, err := registry.ImageReferenceInStubRegistry(ctx, imageName+":%s-%s.sig", digest.Algorithm, digest.Hex)
	if err != nil {
		return ctx, err
	}

	// push to the registry
	err = remote.Write(ref, singnatureImage)
	if err != nil {
		return ctx, err
	}

	if state.Signatures == nil {
		state.Signatures = make(map[string]string)
	}

	state.Signatures[imageName] = ref.String()

	return ctx, nil
}

// createAndPushAttestation for a named image in the Context creates an attestation
// image, same as `cosign attest` or Tekton Chains would, and pushes it to the stub
// registry as a new tag for that image akin to how cosign and Tekton Chains do it
func createAndPushAttestation(ctx context.Context, imageName, keyName string) (context.Context, error) {
	var state *imageState
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if state.Attestations[imageName] != "" {
		// we already created the attestation
		return ctx, nil
	}

	image, err := imageFrom(ctx, imageName)
	if err != nil {
		return ctx, err
	}

	// generates a mostly-empty statement, but with the required fields already filled in
	// at this point we could add more data to the statement but the minimum works, we'll
	// need to add more data to the attestation in more elaborate tests so:
	// TODO: create a hook to add more data to the attestation
	statement, err := attestation.CreateStatementFor(imageName, image)
	if err != nil {
		return ctx, err
	}

	// signs the attestation with the named key
	signedAttestation, err := attestation.SignStatement(ctx, keyName, *statement)
	if err != nil {
		return ctx, err
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signedAttestation)

	attestationLayer, err := static.NewAttestation(signedAttestation)
	if err != nil {
		return ctx, err
	}

	// creates the attestation image with the correct media type and config and appends
	// the attestation layer to it
	attestationImage := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	attestationImage = mutate.ConfigMediaType(attestationImage, types.OCIConfigJSON)
	attestationImage, err = mutate.Append(attestationImage, mutate.Addendum{
		MediaType: cosigntypes.DssePayloadType,
		Layer:     attestationLayer,
		Annotations: map[string]string{
			static.SignatureAnnotationKey: signatureBase64,
		},
	})
	if err != nil {
		return ctx, err
	}

	digest, err := image.Digest()
	if err != nil {
		return ctx, err
	}

	// the name of the image + the <hash>.att tag
	ref, err := registry.ImageReferenceInStubRegistry(ctx, imageName+":%s-%s.att", digest.Algorithm, digest.Hex)
	if err != nil {
		return ctx, err
	}

	// push to the registry
	err = remote.Write(ref, attestationImage)
	if err != nil {
		return ctx, err
	}

	if state.Attestations == nil {
		state.Attestations = make(map[string]string)
	}

	state.Attestations[imageName] = ref.String()

	return ctx, nil
}

// createAndPushImage creates a small 4K random image with 2 layers and pushes it to
// the stub image registry
func createAndPushImage(ctx context.Context, imageName string) (context.Context, error) {
	var state *imageState
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if state.Attestations[imageName] != "" {
		// we already created the image
		return ctx, nil
	}

	img, err := random.Image(4096, 2)
	if err != nil {
		return ctx, err
	}

	ref, err := registry.ImageReferenceInStubRegistry(ctx, imageName)
	if err != nil {
		return ctx, err
	}

	// push to the registry
	err = remote.Write(ref, img)
	if err != nil {
		return ctx, err
	}

	if state.Images == nil {
		state.Images = make(map[string]string)
	}

	state.Images[imageName] = ref.String()

	return ctx, nil
}

// AttestationFrom finds the raw attestation created by the createAndPushAttestation
func AttestationFrom(ctx context.Context, imageName string) ([]byte, error) {
	state := testenv.FetchState[imageState](ctx)

	refStr := state.Attestations[imageName]

	if refStr == "" {
		return nil, fmt.Errorf("no attestation found for image %s, did you create a attestation beforehand", imageName)
	}

	ref, err := name.ParseReference(refStr)
	if err != nil {
		return nil, err
	}

	image, err := remote.Image(ref)
	if err != nil {
		return nil, err
	}

	layers, err := image.Layers()
	if err != nil {
		return nil, err
	}

	for _, layer := range layers {
		if mediaType, err := layer.MediaType(); err != nil {
			return nil, err
		} else if mediaType == cosigntypes.DssePayloadType {
			blob, err := layer.Uncompressed()
			if err != nil {
				return nil, err
			}
			defer blob.Close()

			return io.ReadAll(blob)
		}
	}

	return nil, fmt.Errorf("no attestation found for image %s, did you create a attestation beforehand", imageName)
}

// AddStepsTo adds Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^an image named "([^"]*)"$`, createAndPushImage)
	sc.Step(`^a valid image signature of "([^"]*)" image signed by the "([^"]*)" key$`, createAndPushImageSignature)
	sc.Step(`^a valid attestation of "([^"]*)" signed by the "([^"]*)" key$`, createAndPushAttestation)
}
