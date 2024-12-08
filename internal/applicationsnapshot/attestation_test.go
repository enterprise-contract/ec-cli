// Copyright The Enterprise Contract Contributors
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

//go:build unit

package applicationsnapshot

import (
	"encoding/json"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/in-toto/in-toto-golang/in_toto"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/stretchr/testify/assert"

	"github.com/enterprise-contract/ec-cli/internal/evaluator"
)

func TestAttestationReport(t *testing.T) {
	cases := []struct {
		name       string
		components []Component
	}{
		{
			name:       "no components",
			components: []Component{},
		},
		{
			name: "no attestations",
			components: []Component{
				{},
				{},
			},
		},
		{
			name: "one attestation",
			components: []Component{
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/image:tag",
					},
					Attestations: []AttestationResult{
						att("attestation1"),
					},
				},
			},
		},
		{
			name: "two components two attestations",
			components: []Component{
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/image1:tag",
					},
					Attestations: []AttestationResult{
						att("attestation1"),
						att("attestation2"),
					},
				},
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/image2:tag",
					},
					Attestations: []AttestationResult{
						att("attestation3"),
						att("attestation4"),
					},
				},
			},
		},
		{
			name: "mix of components and attestations",
			components: []Component{
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/image1:tag",
					},
					Attestations: []AttestationResult{
						att("attestation1"),
					},
				},
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/image2:tag",
					},
				},
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/image3:tag",
					},
					Attestations: []AttestationResult{
						att("attestation2"),
						att("attestation3"),
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Report{
				Components: c.components,
			}
			b, err := r.renderAttestations()
			assert.NoError(t, err)

			snaps.MatchSnapshot(t, string(b))
		})
	}
}

func TestAttestations(t *testing.T) {
	statement := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          "my-type",
			PredicateType: "my-predicate-type",
			Subject:       []in_toto.Subject{},
		},
	}
	data, err := json.Marshal(statement)
	assert.NoError(t, err)

	components := []Component{
		{
			SnapshotComponent: app.SnapshotComponent{Name: "component1"},
			Violations: []evaluator.Result{
				{
					Message: "violation1",
				},
			},
			Attestations: []AttestationResult{
				{
					Statement: data,
				},
			},
		},
	}

	report := Report{Components: components}
	att, err := report.attestations()
	assert.NoError(t, err)
	assert.Equal(t, []in_toto.Statement{statement}, att)
}

func att(data string) AttestationResult {
	return AttestationResult{
		Statement: []byte(data),
	}
}
