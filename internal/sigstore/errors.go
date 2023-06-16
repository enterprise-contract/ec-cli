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

package sigstore

import (
	"fmt"

	"github.com/sigstore/cosign/v2/pkg/cosign"

	"github.com/enterprise-contract/ec-cli/internal/policy"
)

const missingSignatureMessage = "No image signatures found matching the given public key. " +
	"Verify the correct public key was provided, " +
	"and a signature was created."

const missingAttestationMessage = "No image attestations found matching the given public key. " +
	"Verify the correct public key was provided, " +
	"and one or more attestations were created."

// WrapCosignErrorMessage wraps the message from the given error indicating the
// type of check that was performed. It may also completey change the  message
// with a more helpful one in some cases.
func WrapCosignErrorMessage(err error, checkType string, p policy.Policy) string {
	// When NOT using the keyless workflow, the "no matching signatures" error from cosign lacks
	// any useful information. Only in such case, change the error message to something more
	// helpful.
	if p == nil || !p.Keyless() {
		var noMatchingErr string
		var msg string
		switch checkType {
		case "signature":
			noMatchingErr = cosign.ErrNoMatchingSignaturesType
			msg = missingSignatureMessage
		case "attestation":
			noMatchingErr = cosign.ErrNoMatchingAttestationsType
			msg = missingAttestationMessage
		}
		if vErr, ok := err.(*cosign.VerificationError); ok && vErr.ErrorType() == noMatchingErr && msg != "" {
			return msg
		}
	}
	return fmt.Sprintf("Image %s check failed: %s", checkType, err)
}
