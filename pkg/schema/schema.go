// Copyright Red Hat.
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

package schema

import (
	_ "embed"
	"encoding/json"

	"github.com/qri-io/jsonschema"
)

var SLSA_Provenance_v0_2 jsonschema.Schema

//go:embed slsa_provenance_v0.2.json
var slsa_provenance_v0_2_json string

func init() {
	jsonschema.RegisterKeyword("uniqueKeys", newUniqueKeys)

	jsonschema.LoadDraft2019_09()

	if err := json.Unmarshal([]byte(slsa_provenance_v0_2_json), &SLSA_Provenance_v0_2); err != nil {
		panic(err)
	}
}
