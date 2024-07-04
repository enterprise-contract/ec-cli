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

//go:build integration

package validate

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/output"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/utils"
	"github.com/enterprise-contract/ec-cli/internal/utils/oci"
	"github.com/enterprise-contract/ec-cli/internal/utils/oci/fake"
)

func TestEvaluatorLifecycle(t *testing.T) {
	ctx := utils.WithFS(context.Background(), afero.NewMemMapFs())
	client := fake.FakeClient{}
	commonMockClient(&client)
	ctx = oci.WithClient(ctx, &client)

	noEvaluators := 100

	evaluators := make([]*mockEvaluator, 0, noEvaluators)
	expectations := make([]*mock.Call, 0, noEvaluators)

	for i := 0; i < noEvaluators; i++ {
		e := mockEvaluator{}
		call := e.On("Evaluate", ctx, mock.Anything).Return([]evaluator.Outcome{}, evaluator.Data{}, nil)

		evaluators = append(evaluators, &e)
		expectations = append(expectations, call)
	}

	for i := 0; i < noEvaluators; i++ {
		evaluators[i].On("Destroy").NotBefore(expectations...)
	}

	newConftestEvaluator = func(_ context.Context, s []source.PolicySource, _ evaluator.ConfigProvider, _ v1alpha1.Source) (evaluator.Evaluator, error) {
		idx, err := strconv.Atoi(s[0].PolicyUrl())
		require.NoError(t, err)

		return evaluators[idx], nil
	}
	t.Cleanup(func() {
		newConftestEvaluator = evaluator.NewConftestEvaluator
	})

	validate := func(_ context.Context, component app.SnapshotComponent, _ *app.SnapshotSpec, _ policy.Policy, evaluators []evaluator.Evaluator, _ bool) (*output.Output, error) {
		for _, e := range evaluators {
			_, _, err := e.Evaluate(ctx, []string{})
			require.NoError(t, err)
		}

		return &output.Output{ImageURL: component.ContainerImage}, nil
	}

	validateImageCmd := validateImageCmd(validate)
	cmd := setUpCobra(validateImageCmd)

	cmd.SetContext(ctx)

	effectiveTimeTest := time.Now().UTC().Format(time.RFC3339Nano)

	sources := make([]string, 0, noEvaluators)
	for i := 0; i < noEvaluators; i++ {
		sources = append(sources, fmt.Sprintf(`{"policy": ["%d"]}`, i))
	}

	cmd.SetArgs([]string{
		"validate",
		"image",
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": %s, "sources": [%s]}`, utils.TestPublicKeyJSON, strings.Join(sources, ", ")),
		"--effective-time",
		effectiveTimeTest,
		"--ignore-rekor",
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
}
