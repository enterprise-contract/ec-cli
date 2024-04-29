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

//go:build unit || integration

package validate

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/mock"

	"github.com/enterprise-contract/ec-cli/cmd/root"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
)

type MockRemoteClient struct {
	mock.Mock
}

func (m *MockRemoteClient) Get(ref name.Reference) (*remote.Descriptor, error) {
	args := m.Called(ref)
	result := args.Get(0)
	if result != nil {
		return result.(*remote.Descriptor), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockRemoteClient) Index(ref name.Reference) (v1.ImageIndex, error) {
	args := m.Called(ref)
	result := args.Get(0)
	if result != nil {
		return args.Get(0).(v1.ImageIndex), args.Error(1)
	}
	return nil, args.Error(1)
}

func commonMockClient(mockClient *MockRemoteClient) {
	imageManifestJson := `{"mediaType": "application/vnd.oci.image.manifest.v1+json"}`
	imageManifestJsonBytes := []byte(imageManifestJson)
	// TODO: Replace mock.Anything calls with specific values
	mockClient.On("Get", mock.Anything).Return(&remote.Descriptor{Manifest: imageManifestJsonBytes}, nil)
}

type mockEvaluator struct {
	mock.Mock
}

func (e *mockEvaluator) Evaluate(ctx context.Context, inputs []string) ([]evaluator.Outcome, evaluator.Data, error) {
	args := e.Called(ctx, inputs)

	return args.Get(0).([]evaluator.Outcome), args.Get(1).(evaluator.Data), args.Error(2)
}

func (e *mockEvaluator) Destroy() {
	e.Called()
}

func (e *mockEvaluator) CapabilitiesPath() string {
	args := e.Called()

	return args.String(0)
}

func setUpCobra(command *cobra.Command) *cobra.Command {
	validateCmd := NewValidateCmd()
	validateCmd.AddCommand(command)
	cmd := root.NewRootCmd()
	cmd.AddCommand(validateCmd)
	return cmd
}
