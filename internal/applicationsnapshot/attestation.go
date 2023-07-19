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

package applicationsnapshot

import (
	"bytes"
)

func (r *Report) renderAttestations() ([]byte, error) {
	buffy := bytes.Buffer{}

	for i, c := range r.Components {
		if i > 0 && len(c.Attestations) > 0 {
			if err := buffy.WriteByte('\n'); err != nil {
				return nil, err
			}
		}
		for j, a := range c.Attestations {
			if j > 0 {
				if err := buffy.WriteByte('\n'); err != nil {
					return nil, err
				}
			}
			if _, err := buffy.Write(a.Statement()); err != nil {
				return nil, err
			}
		}
	}

	return buffy.Bytes(), nil
}
