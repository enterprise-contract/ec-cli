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

package image

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	openairuntime "github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/rekor/pkg/client"
	rclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/client/pubkey"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"sigs.k8s.io/release-utils/version"
)

var (
	// uaString is meant to resemble the User-Agent sent by browsers with requests.
	// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent
	uaString = fmt.Sprintf("rekor-cli/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH)
)

type getCmdOutput struct {
	Attestation     string
	AttestationType string
	Body            interface{}
	LogIndex        int
	IntegratedTime  int64
	UUID            string
	LogID           string
}

// UserAgent returns the User-Agent string which `rekor-cli` should send with HTTP requests.
func UserAgent() string {
	return uaString
}

func extractDigest(ref string) (string, error) {
	parts := strings.SplitN(ref, "@sha256:", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", fmt.Errorf("no sha256 digest found in %q", ref)
	}
	return parts[1], nil
}

func VerifyVSA(containerImage string, keyPub string) (*index.SearchIndexOK, error) {
	params := index.NewSearchIndexParams()
	params.Query = &models.SearchIndex{}

	digest, err := extractDigest(containerImage)
	if err != nil {
		return nil, fmt.Errorf("extracting digest from %q: %w", containerImage, err)
	}
	params.Query.Hash = digest

	rekorClient, err := client.GetRekorClient("https://rekor.sigstore.dev", client.WithUserAgent(UserAgent()), client.WithRetryCount(5))
	if err != nil {
		return nil, err
	}
	params.Query.PublicKey = &models.SearchIndexPublicKey{}
	params.Query.PublicKey.Format = swag.String(models.SearchIndexPublicKeyFormatX509)

	keyBytes, _ := os.ReadFile(filepath.Clean(keyPub))

	params.Query.PublicKey.Content = strfmt.Base64(keyBytes)

	resp, err := rekorClient.Index.SearchIndex(params)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func ToRekor(vsa []byte, containerImage string, keyRef string) error {
	dirName, err := os.MkdirTemp("", "vsadir-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	blobPath := filepath.Join(dirName, "vsa.json")
	if err := os.WriteFile(blobPath, vsa, 0o644); err != nil {
		return fmt.Errorf("writing VSA blob: %w", err)
	}

	// fmt.Println(fileSHA256(blobPath))

	at := attest.AttestCommand{
		KeyOpts:        options.KeyOpts{KeyRef: keyRef, SkipConfirmation: true, RekorURL: "https://rekor.sigstore.dev"},
		PredicatePath:  blobPath,
		PredicateType:  "https://slsa.dev/verification_summary/v0.1",
		RekorEntryType: "intoto",
		TlogUpload:     true,
	}

	// 5) Run the attest command
	// at := attest.AttestBlobCommand{
	// 	KeyOpts:         options.KeyOpts{KeyRef: keyRef, SkipConfirmation: true, RekorURL: "https://rekor.sigstore.dev"},
	// 	PredicatePath:   blobPath,
	// 	PredicateType:   "https://slsa.dev/verification_summary/v0.1",
	// 	OutputSignature: filepath.Join(dirName, "vsa.signature"),
	// 	RekorEntryType:  "intoto",
	// 	TlogUpload:      true,
	// }

	if err := at.Exec(context.Background(), containerImage); err != nil {
		return fmt.Errorf("attesting image: %w", err)
	}

	return nil
}

func GetByUUID(uuid string) []string {
	var logEntries []string
	if uuid != "" {
		params := entries.NewGetLogEntryByUUIDParams()
		params.SetTimeout(viper.GetDuration("timeout"))
		params.EntryUUID = uuid

		rekorClient, err := client.GetRekorClient("https://rekor.sigstore.dev", client.WithUserAgent(UserAgent()), client.WithRetryCount(5))
		if err != nil {
			fmt.Println(err)
		}
		resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
		if err != nil {
			fmt.Println(err)
		}

		for k, entry := range resp.Payload {
			// retrieve rekor pubkey for verification
			treeID, err := sharding.TreeID(k)
			if err != nil {
				fmt.Println(err)
			}
			verifier, err := loadVerifier(rekorClient, strconv.FormatInt(treeID, 10))
			if err != nil {
				fmt.Printf("retrieving rekor public key: %w", err)
			}

			fmt.Printf("params.EntryUUID: %s\n", params.EntryUUID)
			fmt.Printf("k: %s\n", k)
			if err := compareEntryUUIDs(params.EntryUUID, k); err != nil {
				fmt.Printf("error comparing entry UUIDs: %w\n", err)
			}

			// verify log entry
			if entry.Body != nil {
				fmt.Printf("entry: %#v\n", entry)
			} else {
				fmt.Printf("entry is empty\n")
			}
			if err := verify.VerifyLogEntry(context.Background(), &entry, verifier); err != nil {
				fmt.Printf("unable to verify entry was added to log: %w", err)
			}

			e, _ := parseEntry(k, entry)
			logEntries = append(logEntries, e.Attestation)

		}
	}
	return logEntries
}

func parseEntry(uuid string, e models.LogEntryAnon) (*getCmdOutput, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), openairuntime.JSONConsumer())
	if err != nil {
		return nil, err
	}
	eimpl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}

	obj := getCmdOutput{
		Body:           eimpl,
		UUID:           uuid,
		IntegratedTime: *e.IntegratedTime,
		LogIndex:       int(*e.LogIndex),
		LogID:          *e.LogID,
	}

	if e.Attestation != nil {
		obj.Attestation = string(e.Attestation.Data)
	}

	return &obj, nil
}

func compareEntryUUIDs(requestEntryUUID string, responseEntryUUID string) error {
	requestUUID, err := sharding.GetUUIDFromIDString(requestEntryUUID)
	if err != nil {
		return err
	}
	responseUUID, err := sharding.GetUUIDFromIDString(responseEntryUUID)
	if err != nil {
		return err
	}
	// Compare UUIDs.
	if requestUUID != responseUUID {
		return fmt.Errorf("unexpected entry returned from rekor server: expected %s, got %s", requestEntryUUID, responseEntryUUID)
	}
	// If the request contains a Tree ID, then compare that.
	requestTreeID, err := sharding.GetTreeIDFromIDString(requestEntryUUID)
	if err != nil {
		if errors.Is(err, sharding.ErrPlainUUID) {
			// The request did not contain a Tree ID, we're good.
			return nil
		}
		// The request had a bad Tree ID, error out.
		return err
	}
	// We requested an entry from a given Tree ID.
	responseTreeID, err := sharding.GetTreeIDFromIDString(responseEntryUUID)
	if err != nil {
		if errors.Is(err, sharding.ErrPlainUUID) {
			// The response does not contain a Tree ID, we can only do so much.
			// Old rekor instances may not have returned one.
			return nil
		}
		return err
	}
	// We have Tree IDs. Compare.
	if requestTreeID != responseTreeID {
		return fmt.Errorf("unexpected entry returned from rekor server: expected %s, got %s", requestEntryUUID, responseEntryUUID)
	}
	return nil
}

func loadVerifier(rekorClient *rclient.Rekor, treeID string) (signature.Verifier, error) {
	publicKey := viper.GetString("rekor_server_public_key")
	if publicKey == "" {
		// fetch key from server
		keyResp, err := rekorClient.Pubkey.GetPublicKey(pubkey.NewGetPublicKeyParams().WithTreeID(swag.String(treeID)))
		if err != nil {
			return nil, err
		}
		publicKey = keyResp.Payload
	}

	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("failed to decode public key of server")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return signature.LoadVerifier(pub, crypto.SHA256)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	// 2) Create a new SHA‑256 hash
	hasher := sha256.New()

	// 3) Copy the file's contents into the hash
	if _, err := io.Copy(hasher, f); err != nil {
		return "", fmt.Errorf("hashing file: %w", err)
	}

	// 4) Compute the final digest and hex‑encode it
	sum := hasher.Sum(nil)
	return hex.EncodeToString(sum), nil
}
