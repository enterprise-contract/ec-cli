// Copyright 2022 Red Hat, Inc.
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

package policy

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/open-policy-agent/conftest/output"
)

type VerificationStatus struct {
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

type Output struct {
	ImageSignatureCheck       VerificationStatus   `json:"imageSignatureCheck"`
	AttestationSignatureCheck VerificationStatus   `json:"attestationSignatureCheck"`
	PolicyCheck               []output.CheckResult `json:"policyCheck"`
	ExitCode                  int                  `json:"-"`
}

func (o *Output) SetImageSignatureCheck(passed bool, message string) {
	o.ImageSignatureCheck.Passed = passed
	o.ImageSignatureCheck.Message = message
}

func (o *Output) SetAttestationSignatureCheck(passed bool, message string) {
	o.AttestationSignatureCheck.Passed = passed
	o.AttestationSignatureCheck.Message = message
}

func (o *Output) SetPolicyCheck(results []output.CheckResult) {
	for r := range results {
		if results[r].FileName == "-" {
			results[r].FileName = ""
		}

		results[r].Queries = nil
	}
	o.PolicyCheck = results
	o.ExitCode = output.ExitCode(results)
}

func (o *Output) Print(out io.Writer) error {
	return o.print(out, "")
}

func (o *Output) print(out io.Writer, indent string) error {
	e := json.NewEncoder(out)
	e.SetIndent(indent, "\t")
	err := e.Encode(o)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	return nil
}

type Outputs []*Output

func (o Outputs) Print(out io.Writer) error {
	fmt.Fprint(out, "[")
	first := true
	for _, output := range o {
		if first {
			fmt.Fprint(out, "\n\t")
		} else {
			fmt.Fprint(out, "\t,")
		}
		first = false
		err := output.print(out, "\t")
		if err != nil {
			return err
		}

	}
	fmt.Fprint(out, "]\n")
	return nil
}
