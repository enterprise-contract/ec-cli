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
	"testing"

	"github.com/open-policy-agent/conftest/output"
	"github.com/redhat-appstudio/application-api/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"k8s.io/kubernetes/test/utils/junit"

	o "github.com/enterprise-contract/ec-cli/internal/output"
)

type mapper struct {
	mock.Mock
}

func (m *mapper) mappy(r output.Result) int {
	args := m.Called(r)

	return args.Int(0)
}

func TestMapResults(t *testing.T) {
	m := mapper{}
	m.On("mappy", mock.Anything).Return(0).Once()
	m.On("mappy", mock.Anything).Return(1).Once()
	m.On("mappy", mock.Anything).Return(2).Once()

	mapped := mapResults([]output.Result{{}, {}, {}}, m.mappy)

	assert.Equal(t, []int{0, 1, 2}, mapped)

	m.AssertExpectations(t)
}

func TestAsTestCase(t *testing.T) {
	cases := []struct {
		name     string
		result   output.Result
		expected *junit.TestCase
	}{
		{
			name:     "nil",
			expected: &junit.TestCase{},
		},
		{
			name:     "trivial",
			result:   output.Result{Message: "msg"},
			expected: &junit.TestCase{Name: "msg", Classname: "msg"},
		},
		{
			name:     "with code",
			result:   output.Result{Message: "msg", Metadata: map[string]interface{}{"code": "a.b.c"}},
			expected: &junit.TestCase{Name: "a.b.c: msg", Classname: "a.b.c: msg"},
		},
		{
			name:     "with metadata",
			result:   output.Result{Message: "msg", Metadata: map[string]interface{}{"x": "1", "y": "2", "z": "3"}},
			expected: &junit.TestCase{Name: "msg [x=1, y=2, z=3]", Classname: "msg [x=1, y=2, z=3]"},
		},
		{
			name:     "with code and metadata",
			result:   output.Result{Message: "msg", Metadata: map[string]interface{}{"code": "a.b.c", "x": "1", "y": "2", "z": "3"}},
			expected: &junit.TestCase{Name: "a.b.c: msg [x=1, y=2, z=3]", Classname: "a.b.c: msg [x=1, y=2, z=3]"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := asTestCase(c.result)

			assert.Equal(t, c.expected, got)
		})
	}
}

func TestToJunit(t *testing.T) {
	cases := []struct {
		name     string
		report   Report
		expected testSuites
	}{
		{
			name: "trivial",
		},
		{
			name: "one trivial component",
			report: Report{
				Components: []Component{
					{
						SnapshotComponent: v1alpha1.SnapshotComponent{
							Name:           "Name",
							ContainerImage: "registry.io/repository/image:tag",
						},
						Signatures: []o.EntitySignature{
							{
								KeyID:     "keyID1",
								Signature: "signature1",
							},
							{
								KeyID:     "keyID2",
								Signature: "signature2",
								Metadata: map[string]string{
									"C": "D",
									"A": "B",
									"B": "C",
								},
							},
						},
						Violations: []output.Result{
							{
								Message: "violation",
								Metadata: map[string]interface{}{
									"code": "violation",
								},
							},
						},
						Warnings: []output.Result{
							{
								Message: "warning",
								Metadata: map[string]interface{}{
									"code": "warning",
								},
							},
						},
						Successes: []output.Result{
							{
								Message: "success",
								Metadata: map[string]interface{}{
									"code": "success",
								},
							},
						},
						Success: true,
					},
				},
				Key:     "key",
				Success: true,
			},
			expected: testSuites{
				TestSuites: []*junit.TestSuite{
					{
						Name: "Name (registry.io/repository/image:tag)",
						Properties: []*junit.Property{
							{
								Name:  "image",
								Value: "registry.io/repository/image:tag",
							},
							{
								Name:  "key",
								Value: "key",
							},
							{
								Name:  "success",
								Value: "true",
							},
							{
								Name:  "keyId",
								Value: "keyID1",
							},
							{
								Name:  "signature",
								Value: "signature1",
							},
							{
								Name:  "keyId",
								Value: "keyID2",
							},
							{
								Name:  "signature",
								Value: "signature2",
							},
							{
								Name:  "metadata.A",
								Value: "B",
							},
							{
								Name:  "metadata.B",
								Value: "C",
							},
							{
								Name:  "metadata.C",
								Value: "D",
							},
						},
						TestCases: []*junit.TestCase{
							{
								Name:      "success: success",
								Classname: "success: success",
							},
							{
								Name:      "violation: violation",
								Classname: "violation: violation",
								Failures: []*junit.Failure{
									{
										Message: "violation",
										Value:   "violation",
									},
								},
							},
							{
								Name:      "warning: warning",
								Classname: "warning: warning",
								Skipped:   "warning",
							},
						},
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.report.toJUnit()

			c.expected.update()

			assert.Equal(t, c.expected, got)
		})
	}
}
