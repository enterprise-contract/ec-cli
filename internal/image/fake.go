// Copyright The Conforma Contributors
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

package image

import (
	"encoding/json"

	"github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"

	"github.com/conforma/cli/internal/signature"
)

type fakeAtt struct {
	statement in_toto.ProvenanceStatementSLSA02
}

func (f fakeAtt) Statement() []byte {
	bytes, err := json.Marshal(f.statement)
	if err != nil {
		panic(err)
	}
	return bytes
}

func (f fakeAtt) Type() string {
	return in_toto.StatementInTotoV01
}

func (f fakeAtt) PredicateType() string {
	return v02.PredicateSLSAProvenance
}

func (f fakeAtt) Signatures() []signature.EntitySignature {
	return []signature.EntitySignature{}
}

func (f fakeAtt) Subject() []in_toto.Subject {
	return []in_toto.Subject{}
}
