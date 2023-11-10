// Copyright The Enterprise Contract Contributors
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

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	app "github.com/redhat-appstudio/application-api/api/v1alpha1"
	"github.com/stretchr/testify/assert"

	"github.com/enterprise-contract/ec-cli/internal/attestation"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/signature"
	"github.com/enterprise-contract/ec-cli/internal/utils"
	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
)

type provenance struct {
	statement in_toto.Statement
	data      []byte
}

// type Attestation interface {
// 	Type() string
// 	PredicateType() string
// 	Statement() []byte
// 	Signatures() []signature.EntitySignature
// 	Subject() []in_toto.Subject
// }

func (p provenance) Type() string {
	return in_toto.StatementInTotoV01
}

func (p provenance) PredicateType() string {
	return p.statement.StatementHeader.PredicateType
}

func (p provenance) Statement() []byte {
	return p.data
}

func (p provenance) Signatures() []signature.EntitySignature {
	return []signature.EntitySignature{}
}

func (p provenance) Subject() []in_toto.Subject {
	return p.statement.Subject
}

//	statement: in_toto.Statement{
//		Type:          "https://in-toto.io/Statement/v1",
//		PredicateType: "https://enterprisecontract.dev/verification_summary/v1",
//		Subject:       []in_toto.Subject{},
//	},
func TestNewVSA(t *testing.T) {
	components := []Component{
		{
			SnapshotComponent: app.SnapshotComponent{Name: "component1"},
			Violations: []evaluator.Result{
				{
					Message: "violation1",
				},
			},
			Attestations: []attestation.Attestation{
				provenance{
					statement: in_toto.Statement{},
				},
			},
		},
	}

	testPolicy, err := policy.NewPolicy(context.Background(), policy.Options{
		PublicKey:     utils.TestPublicKey,
		EffectiveTime: policy.Now,
		PolicyRef:     toJson(&ecc.EnterpriseContractPolicySpec{PublicKey: utils.TestPublicKey}),
	})
	assert.NoError(t, err)

	report, err := NewReport("snappy", components, testPolicy, "data here", nil)
	assert.NoError(t, err)

	expected := ProvenanceStatementVSA{
		StatementHeader: in_toto.StatementHeader{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: "https://enterprisecontract.dev/verification_summary/v1",
			Subject:       nil,
		},
		Predicate: report,
	}
	vsa, err := NewVSA(report)
	assert.NoError(t, err)
	assert.Equal(t, expected, vsa)
}

func toJson(policy any) string {
	newInline, err := json.Marshal(policy)
	if err != nil {
		panic(fmt.Errorf("invalid JSON: %w", err))
	}
	return string(newInline)
}
