// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package applicationsnapshot

import (
	"github.com/in-toto/in-toto-golang/in_toto"
)

const (
	// Make it visible elsewhere
	PredicateVSAProvenance = "https://conforma.dev/verification_summary/v1"
	StatmentVSA            = "https://in-toto.io/Statement/v1"
)

type ProvenanceStatementVSA struct {
	in_toto.StatementHeader
	Predicate Report `json:"predicate"`
}

func NewVSA(report Report) (ProvenanceStatementVSA, error) {
	subjects, err := getSubjects(report)
	if err != nil {
		return ProvenanceStatementVSA{}, err
	}

	return ProvenanceStatementVSA{
		StatementHeader: in_toto.StatementHeader{
			Type:          StatmentVSA,
			PredicateType: PredicateVSAProvenance,
			Subject:       subjects,
		},
		Predicate: report,
	}, nil
}

func getSubjects(report Report) ([]in_toto.Subject, error) {
	statements, err := report.attestations()
	if err != nil {
		return []in_toto.Subject{}, err
	}

	var subjects []in_toto.Subject
	for _, stmt := range statements {
		subjects = append(subjects, stmt.Subject...)
	}
	return subjects, nil
}
