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

// Stub implementation of Rekord
package rekor

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/cucumber/godog"
	"github.com/go-openapi/strfmt"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/crypto"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/image"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/wiremock"
	"github.com/sigstore/rekor/pkg/generated/models"
	intoto "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	"github.com/transparency-dev/merkle/rfc6962"
)

// stubRekordRunning starts the stub apiserver using WireMock
func stubRekordRunning(ctx context.Context) (context.Context, error) {
	return wiremock.StartWiremock(ctx)
}

// randomHex generates a random hex string of the given length
func randomHex(len int) string {
	b := make([]byte, len/2)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(b)
}

// rekorEntryForAttestation given an image name for which attestation has been
// previously performed via image.createAndPushAttestation, creates stub for a
// empty attestation log entry in Rekor
// TODO: match the request closer to the request for the specific lookup, this
//       stub entry will match all lookups, i.e. won't take into account the
//       image digest by whitch the entry is looked up
func rekorEntryForAttestation(ctx context.Context, imageName string) error {
	var logEntry models.LogEntry = models.LogEntry{}

	attestation, err := image.AttestationFrom(ctx, imageName)
	if err != nil {
		return err
	}

	// the body of the log entry is an in-toto payload
	logBody := intoto.NewEntry()

	algorithm := models.IntotoV001SchemaContentPayloadHashAlgorithmSha256
	// the hash should relate to other entries but since we're faking a single
	// entry, not related to other entries -- any random hash-like hex will be
	// okay
	hash := randomHex(64)

	// not used for any signing, we just need the public key in PEM for the
	// in-toto schema below
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return err
	}
	// double-base64 encoding FTW
	publicKey := strfmt.Base64(keyPair.PublicBytes)

	// the only way to set fields of the intoto Entry
	err = logBody.Unmarshal(&models.Intoto{
		Spec: models.IntotoV001Schema{
			Content: &models.IntotoV001SchemaContent{
				Hash: &models.IntotoV001SchemaContentHash{
					Algorithm: &algorithm,
					Value:     &hash,
				},
			},
			PublicKey: &publicKey,
		},
	})
	if err != nil {
		return err
	}

	logBodyBytes, err := logBody.Canonicalize(ctx)
	if err != nil {
		return err
	}

	// needs to match the hash over body bytes
	entryUUID := rfc6962.DefaultHasher.HashLeaf(logBodyBytes)

	// fill in the entry with the attestation and in-toto entry for the log
	logEntry[hex.EncodeToString(entryUUID)] = models.LogEntryAnon{
		Attestation: &models.LogEntryAnonAttestation{
			Data: attestation,
		},
		Body: base64.StdEncoding.EncodeToString(logBodyBytes),
	}

	// the response is in application/json
	body, err := json.Marshal([]models.LogEntry{logEntry})
	if err != nil {
		return err
	}

	// return this entry for any lookup in Rekor
	return wiremock.StubFor(ctx, wiremock.Post(wiremock.URLPathEqualTo("/api/v1/log/entries/retrieve")).
		WillReturn(string(body),
			map[string]string{"Content-Type": "application/json"},
			200,
		))
}

// StubRekor returns the `http://host:port` of the stubbed Rekord
func StubRekor(ctx context.Context) string {
	return wiremock.Endpoint(ctx)
}

// AddStepsTo adds Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^stub rekord running$`, stubRekordRunning)
	sc.Step(`^a valid Rekor entry for attestation of "([^"]*)"$`, rekorEntryForAttestation)
}
