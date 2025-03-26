// Copyright The Conforma Contributors
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

package tracing

import (
	"context"
	"fmt"
	"testing"
)

var parse_cases = []struct {
	given    string
	expected Trace
}{
	{"0", None},
	{"1", Default},
	{"false", None},
	{"true", Default},
	{"False", None},
	{"True", Default},
	{"F", None},
	{"T", Default},
	{"FALSE", None},
	{"TRUE", Default},
	{"none", None},
	{"None", None},
	{"perf", Perf},
	{"cpu", CPU},
	{"mem", Memory},
	{"opa", Opa},
	{"log", Log},
	{"all", All},
	{"none,opa", None},
	{"all, perf", All},
	{"perf, Opa", Perf | Opa},
	{"", Default},
	{",Opa", Default | Opa},
	{"perf,", Default | Perf},
}

func TestParseTrace(t *testing.T) {
	for _, c := range parse_cases {
		t.Run(fmt.Sprintf("%s => %d", c.given, c.expected), func(t *testing.T) {
			if got := ParseTrace(c.given); got != c.expected {
				t.Errorf(`ParseTrace("%s") = %d, expected %d`, c.given, got, c.expected)
			}
		})
	}
}

func TestString(t *testing.T) {
	cases := []struct {
		value    Trace
		expected string
	}{
		{None, "none"},
		{Default, "log"},
		{Perf, "perf"},
		{CPU, "cpu"},
		{Memory, "mem"},
		{Opa, "opa"},
		{Log, "log"},
		{All, "perf,cpu,mem,opa,log"},
		{Perf | Opa, "perf,opa"},
		{Log | Opa, "opa,log"},
		{Perf | CPU | Memory | Opa | Log, "perf,cpu,mem,opa,log"},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%d => %s", c.value, c.expected), func(t *testing.T) {
			if got := c.value.String(); got != c.expected {
				t.Errorf(`string("%d") = %s, expected %s`, c.value, got, c.expected)
			}
		})
	}
}

func TestEnabled(t *testing.T) {
	cases := []struct {
		value      Trace
		categories []Trace
		expected   bool
	}{
		{None, []Trace{None}, true},
		{All, []Trace{Opa, Perf, CPU}, true},
		{Opa | Memory, []Trace{CPU, Opa, Perf}, true},
		{Opa | Perf | CPU, []Trace{Memory, Log}, false},
		{Opa | Perf | CPU, []Trace{Opa | Perf, Log}, true},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%v enabled in %d => %v", c.categories, c.value, c.expected), func(t *testing.T) {
			if got := c.value.Enabled(c.categories...); got != c.expected {
				t.Errorf(`%d.Enabled(%v) = %v, expected %v`, c.value, c.categories, got, c.expected)
			}
		})
	}
}

func TestContextStorage(t *testing.T) {
	if FromContext(context.TODO()) != Default {
		t.Error("did not recive the default value from context when unset")
	}

	if FromContext(WithTrace(context.TODO(), Opa)) != Opa {
		t.Error("did not restore the value from context")
	}
}
