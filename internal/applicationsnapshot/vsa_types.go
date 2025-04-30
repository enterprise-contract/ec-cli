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

package applicationsnapshot

// ----------------------------------------------------------------
// Top-level in-toto Statement
// ----------------------------------------------------------------
type Statement struct {
	Type          string             `json:"_type"`
	PredicateType string             `json:"predicateType"`
	Subject       []Subject          `json:"subject"`
	Predicate     StatementPredicate `json:"predicate"`
}

// ----------------------------------------------------------------
// The inner “predicate” wrapper
// ----------------------------------------------------------------
type StatementPredicate struct {
	Type          string    `json:"_type"`
	Predicate     Predicate `json:"predicate"`
	PredicateType string    `json:"predicateType"`
}

// ----------------------------------------------------------------
// The actual verification_summary payload
// ----------------------------------------------------------------
type Predicate struct {
	Component          Component `json:"component"`
	Policy             Policy    `json:"policy"`
	PolicyLevel        string    `json:"policy_level"`
	VerificationResult string    `json:"verification_result"`
	Verifier           Verifier  `json:"verifier"`
}

// ----------------------------------------------------------------
// Subject array element
// ----------------------------------------------------------------
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Verifier identifies who ran the check.
type Verifier struct {
	ID string `json:"id"`
}

// Policy describes which policy was used.
type Policy struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}
