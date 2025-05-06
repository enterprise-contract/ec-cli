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
	"encoding/json"
	"fmt"
	"strings"

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

// splitDigest returns the algorithm and hash from an image reference of the form
//
//	"<repo>@<algorithm>:<hex>"
//
// e.g. "quay.io/foo/bar@sha256:abcdef1234…" → ("sha256", "abcdef1234…", nil)
func splitDigest(ref string) (algorithm, hash string, err error) {
	// find the “@” that precedes the digest
	at := strings.LastIndex(ref, "@")
	if at < 0 {
		return "", "", fmt.Errorf("no digest separator '@' in %q", ref)
	}
	// everything after “@”
	digestPart := ref[at+1:]
	parts := strings.SplitN(digestPart, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid digest format %q", digestPart)
	}
	algorithm, hash = parts[0], parts[1]
	if hash == "" {
		return "", "", fmt.Errorf("empty hash in %q", ref)
	}
	return algorithm, hash, nil
}

func ComponentVSA(comp Component) ([]byte, error) {
	stmt := Predicate{
		Verifier: Verifier{ID: "conforma.dev"},
		Policy: Policy{
			URI: "github.com/enterprise-contract/policy",
			Digest: map[string]string{
				// this needs to be passed in also
				"sha256": "3e1f8b9a4e6e1f795b084fc7e0e18b427826f0d9f78e2dbe7e5a9fd6541bd0e9",
			},
		},
		Component: Component{},
	}

	// 2) Marshal it to JSON bytes
	b, err := json.MarshalIndent(stmt, "", "  ")
	if err != nil {
		panic(err)
	}
	return b, nil
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
