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
	"fmt"
	"mime/multipart"
	"net/textproto"
)

var adapt = func(_ *multipart.Writer) {
	// hook for tests
}

func (r *Report) renderAttestations() ([]byte, error) {
	buffy := bytes.Buffer{}

	w := multipart.NewWriter(&buffy)
	adapt(w)
	defer w.Close()

	for _, c := range r.Components {
		for i, a := range c.Attestations {
			pw, err := w.CreatePart(textproto.MIMEHeader{
				"Content-Disposition": []string{fmt.Sprintf(`attachment; name=%q`, fmt.Sprintf("%s#%d", c.ContainerImage, i))},
				"Content-Type":        []string{a.ContentType()},
			})
			if err != nil {
				return nil, err
			}

			if _, err := pw.Write(a.Statement()); err != nil {
				return nil, err
			}
		}
	}

	return buffy.Bytes(), nil
}
