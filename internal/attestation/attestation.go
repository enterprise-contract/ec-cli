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

package attestation

import (
	"github.com/enterprise-contract/ec-cli/internal/output"
	e "github.com/enterprise-contract/ec-cli/pkg/error"
)

var (
	AT001 = e.NewError("AT001", "No attestation found", e.ErrorExitStatus)
	AT002 = e.NewError("AT002", "Malformed attestation data", e.ErrorExitStatus)
	AT003 = e.NewError("AT003", "Unsupported attestation type", e.ErrorExitStatus)
	AT004 = e.NewError("AT004", "Unsupported attestation predicate type", e.ErrorExitStatus)
)

// Attestation holds the raw attestation data, usually fetched from the
// signature envelope's payload; statement of a particular type and any
// signing information.
type Attestation[T any] interface {
	Data() []byte
	Statement() T
	Signatures() []output.EntitySignature
}
