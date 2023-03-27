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
	"encoding/xml"
	"fmt"
	"sort"
	"strings"

	conftestOutput "github.com/open-policy-agent/conftest/output"
	"golang.org/x/exp/maps"
	"k8s.io/kubernetes/test/utils/junit"
)

type testSuites struct {
	XMLName    xml.Name           `xml:"testsuites"`
	TestSuites []*junit.TestSuite `xml:"testsuite"`
}

func (t *testSuites) update() {
	for _, s := range t.TestSuites {
		s.Update()
	}
}

// mapResults maps an slice of Conftest results to a slice of arbitrary types
// given a mapper function
func mapResults[T any](results []conftestOutput.Result, m func(conftestOutput.Result) T) []T {
	mapped := make([]T, 0, len(results))
	for _, r := range results {
		mapped = append(mapped, m(r))
	}

	return mapped
}

func asTestCase(r conftestOutput.Result) *junit.TestCase {
	meta := maps.Clone(r.Metadata)
	delete(meta, "code")

	metaDesc := make([]string, 0, 3)
	for k, v := range meta {
		metaDesc = append(metaDesc, fmt.Sprintf("%s=%v", k, v))
	}

	desc := ""
	if len(metaDesc) > 0 {
		sort.Strings(metaDesc)
		desc = " [" + strings.Join(metaDesc, ", ") + "]"
	}

	name := fmt.Sprintf("%s%s", r.Message, desc)

	if code, ok := r.Metadata["code"].(string); ok {
		name = fmt.Sprintf("%s: %s", code, name)
	}

	return &junit.TestCase{
		Name:      name,
		Classname: name, // some reporting tools might require Classname as well
	}
}

// toJUnit returns a version of the report in JUnit XML format
func (r *Report) toJUnit() testSuites {
	report := testSuites{}

	for _, component := range r.Components {
		properties := []*junit.Property{
			{
				Name:  "image",
				Value: component.ContainerImage,
			}, {
				Name:  "key",
				Value: r.Key,
			}, {
				Name:  "success",
				Value: fmt.Sprint(component.Success),
			},
		}

		for _, s := range component.Signatures {
			properties = append(properties, &junit.Property{
				Name:  "keyId",
				Value: s.KeyID,
			}, &junit.Property{
				Name:  "signature",
				Value: s.Signature,
			})

			metaProps := make([]*junit.Property, 0, len(s.Metadata))
			for k, v := range s.Metadata {
				metaProps = append(metaProps, &junit.Property{
					Name:  "metadata." + k,
					Value: v,
				})
			}

			sort.SliceStable(metaProps, func(i, j int) bool {
				return strings.Compare(metaProps[i].Name, metaProps[j].Name) < 0
			})

			properties = append(properties, metaProps...)
		}

		suite := junit.TestSuite{
			Timestamp:  r.created,
			Name:       fmt.Sprintf("%s (%s)", component.Name, component.ContainerImage),
			Properties: properties,
		}

		suite.TestCases = mapResults(component.Successes, asTestCase)

		suite.TestCases = append(suite.TestCases, mapResults(component.Violations, func(r conftestOutput.Result) *junit.TestCase {
			c := asTestCase(r)
			c.Failures = append(c.Failures, &junit.Failure{
				Message: r.Message,
				Value:   r.Message,
			})

			return c
		})...)

		suite.TestCases = append(suite.TestCases, mapResults(component.Warnings, func(r conftestOutput.Result) *junit.TestCase {
			c := asTestCase(r)
			c.Skipped = r.Message

			return c
		})...)

		suite.Update()

		report.TestSuites = append(report.TestSuites, &suite)
	}

	return report
}
