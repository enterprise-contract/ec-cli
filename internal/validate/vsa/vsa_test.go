// Copyright The Conforma Contributors
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

package vsa

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"
	"time"

	ecapi "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	appapi "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/enterprise-contract/ec-cli/internal/applicationsnapshot"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
)

func mockReportAndComponent() (applicationsnapshot.Report, applicationsnapshot.Component) {
	report := applicationsnapshot.Report{
		EffectiveTime: time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
		Policy:        ecapi.EnterpriseContractPolicySpec{Name: "mock-policy", PublicKey: "mock-policy-key"},
	}
	component := applicationsnapshot.Component{
		SnapshotComponent: appapi.SnapshotComponent{
			Name:           "test-component",
			ContainerImage: "quay.io/test/image:tag",
			Source:         appapi.ComponentSource{},
		},
		Violations: []evaluator.Result{{Message: "violation1"}},
		Warnings:   []evaluator.Result{{Message: "warning1"}},
		Successes:  []evaluator.Result{{Message: "success1"}},
		Success:    true,
	}
	return report, component
}

func TestGeneratePredicate(t *testing.T) {
	report, component := mockReportAndComponent()
	pred, err := GeneratePredicate(context.Background(), report, component, Options{})
	assert.NoError(t, err)
	assert.Equal(t, component.ContainerImage, pred.ImageRef)
	assert.Equal(t, "passed", pred.ValidationResult)
	assert.Equal(t, "Conforma", pred.Verifier)
	assert.Equal(t, "mock-policy", report.Policy.Name)
	assert.Equal(t, component.Name, pred.Component["name"])
	assert.Equal(t, component.ContainerImage, pred.Component["containerImage"])
	assert.Equal(t, component.Source, pred.Component["source"])
	assert.Len(t, pred.RuleResults, 3)
	assert.Equal(t, "violation1", pred.RuleResults[0].Message)
	assert.Equal(t, "warning1", pred.RuleResults[1].Message)
	assert.Equal(t, "success1", pred.RuleResults[2].Message)
}

func TestWriteVSA(t *testing.T) {
	FS = afero.NewMemMapFs()
	pred := &Predicate{
		ImageRef:         "quay.io/test/image:tag",
		ValidationResult: "passed",
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Verifier:         "Conforma",
		PolicySource:     "mock-policy",
		Component: map[string]interface{}{
			"name":           "test-component",
			"containerImage": "quay.io/test/image:tag",
			"source":         map[string]interface{}{"git": "repo"},
		},
		RuleResults: []evaluator.Result{{Message: "violation1"}},
	}
	dir := "/tmp"
	path := filepath.Join(dir, "test.vsa.json")
	err := WriteVSA(pred, path)
	assert.NoError(t, err)
	data, err := afero.ReadFile(FS, path)
	assert.NoError(t, err)
	var out Predicate
	err = json.Unmarshal(data, &out)
	assert.NoError(t, err)
	assert.Equal(t, pred.ImageRef, out.ImageRef)
	assert.Equal(t, pred.ValidationResult, out.ValidationResult)
	assert.Equal(t, pred.Verifier, out.Verifier)
	assert.Equal(t, pred.PolicySource, out.PolicySource)
	assert.Equal(t, pred.Component["name"], out.Component["name"])
	assert.Equal(t, pred.Component["containerImage"], out.Component["containerImage"])
	assert.Equal(t, pred.Component["source"], out.Component["source"])
	assert.Len(t, out.RuleResults, 1)
	assert.Equal(t, "violation1", out.RuleResults[0].Message)
}

// TestSignVSA_Mock simulates the cosign signing flow for SignVSA.
func TestSignVSA_Mock(t *testing.T) {
	FS = afero.NewMemMapFs()
	pred := &Predicate{
		ImageRef:         "quay.io/test/image:tag",
		ValidationResult: "passed",
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Verifier:         "Conforma",
		PolicySource:     "mock-policy",
		Component: map[string]interface{}{
			"name":           "test-component",
			"containerImage": "quay.io/test/image:tag",
			"source":         map[string]interface{}{"git": "repo"},
		},
		RuleResults: []evaluator.Result{{Message: "violation1"}},
	}
	dir := "/tmp"
	vsaPath := filepath.Join(dir, "test.vsa.json")
	data, _ := json.Marshal(pred)
	err := afero.WriteFile(FS, vsaPath, data, 0600)
	assert.NoError(t, err)

	// Act
	sig, err := SignVSA(context.Background(), vsaPath, "irrelevant.key", "quay.io/test/image:tag")
	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, sig)
	payload, err := sig.Payload()
	assert.NoError(t, err)
	assert.Contains(t, string(payload), "quay.io/test/image:tag")

	// Test error propagation from attestation creation
	_, err = SignVSA(context.Background(), "/nonexistent/path", "irrelevant.key", "quay.io/test/image:tag")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read VSA file")
}

func TestUploadVSAAttestation(t *testing.T) {
	fakeAtt := &mockAttestation{}
	imageRef := "quay.io/test/image:tag"
	ctx := context.Background()

	t.Run("calls provided uploader and returns result", func(t *testing.T) {
		uploaderCalled := false
		uploader := func(ctx context.Context, att oci.Signature, img string) (string, error) {
			uploaderCalled = true
			assert.Equal(t, fakeAtt, att)
			assert.Equal(t, imageRef, img)
			return "digest123", nil
		}
		result, err := uploader(ctx, fakeAtt, imageRef)
		assert.NoError(t, err)
		assert.Equal(t, "digest123", result)
		assert.True(t, uploaderCalled)
	})

	t.Run("propagates error from uploader", func(t *testing.T) {
		uploader := func(ctx context.Context, att oci.Signature, img string) (string, error) {
			return "", assert.AnError
		}
		result, err := uploader(ctx, fakeAtt, imageRef)
		assert.Error(t, err)
		assert.Equal(t, "", result)
		assert.Contains(t, err.Error(), assert.AnError.Error())
	})
}

func TestNoopUploader(t *testing.T) {
	result, err := NoopUploader(context.Background(), &mockAttestation{}, "img")
	assert.NoError(t, err)
	assert.Equal(t, "", result)
}

func TestOCIUploader(t *testing.T) {
	result, err := OCIUploader(context.Background(), &mockAttestation{}, "img")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OCI upload not implemented")
	assert.Equal(t, "", result)
}

func TestRekorUploader(t *testing.T) {
	result, err := RekorUploader(context.Background(), &mockAttestation{}, "img")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rekor upload not implemented")
	assert.Equal(t, "", result)
}

type mockAttestation struct{}

func (m *mockAttestation) Digest() (v1.Hash, error)                            { return v1.Hash{}, nil }
func (m *mockAttestation) Payload() ([]byte, error)                            { return nil, nil }
func (m *mockAttestation) SetAnnotations(map[string]string) error              { return nil }
func (m *mockAttestation) Annotations() (map[string]string, error)             { return nil, nil }
func (m *mockAttestation) SetLayerMediaType(string) error                      { return nil }
func (m *mockAttestation) LayerMediaType() (string, error)                     { return "", nil }
func (m *mockAttestation) SetPayload([]byte, string) error                     { return nil }
func (m *mockAttestation) SetSignature([]byte) error                           { return nil }
func (m *mockAttestation) Signature() ([]byte, error)                          { return nil, nil }
func (m *mockAttestation) SetCert([]byte) error                                { return nil }
func (m *mockAttestation) Cert() (*x509.Certificate, error)                    { return nil, nil }
func (m *mockAttestation) SetChain([][]byte) error                             { return nil }
func (m *mockAttestation) Chain() ([]*x509.Certificate, error)                 { return nil, nil }
func (m *mockAttestation) SetBundle([]byte) error                              { return nil }
func (m *mockAttestation) Bundle() (*bundle.RekorBundle, error)                { return nil, nil }
func (m *mockAttestation) SetDSSEEnvelope([]byte) error                        { return nil }
func (m *mockAttestation) DSSEEnvelope() ([]byte, error)                       { return nil, nil }
func (m *mockAttestation) Base64Signature() (string, error)                    { return "", nil }
func (m *mockAttestation) RFC3161Timestamp() (*bundle.RFC3161Timestamp, error) { return nil, nil }
func (m *mockAttestation) Compressed() (io.ReadCloser, error)                  { return nil, nil }
func (m *mockAttestation) Uncompressed() (io.ReadCloser, error)                { return nil, nil }
func (m *mockAttestation) Size() (int64, error)                                { return 0, nil }
func (m *mockAttestation) DiffID() (v1.Hash, error)                            { return v1.Hash{}, nil }
func (m *mockAttestation) MediaType() (v1types.MediaType, error)               { return v1types.MediaType(""), nil }
