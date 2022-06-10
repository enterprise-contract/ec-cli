package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

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
}

func (o *Output) Print() error {
	b, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "\t"); err != nil {
		return fmt.Errorf("indent: %w", err)
	}

	fmt.Fprintln(os.Stdout, out.String())
	return nil
}
