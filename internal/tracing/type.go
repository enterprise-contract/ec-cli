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

package tracing

import (
	"context"
	"strconv"
	"strings"
)

type Trace uint8

const (
	None   Trace = 0
	Perf   Trace = 1 << 0
	CPU    Trace = 1 << 1
	Memory Trace = 1 << 2
	Opa    Trace = 1 << 3
	Log    Trace = 1 << 4
	All    Trace = Perf | CPU | Memory | Opa | Log

	contextKey Trace = 0xff
)

var Default = Log

// ParseTrace returns a Trace for the given comma separated string value
func ParseTrace(s string) Trace {
	// backward compatibility, the flag used to be a boolean on/off, we no longer
	// advertise this
	if v, err := strconv.ParseBool(s); err == nil {
		if v {
			return Default
		} else {
			return None
		}
	}

	trace := None
	for _, t := range strings.Split(s, ",") {
		v := strings.ToLower(strings.TrimSpace(t))
		switch v {
		case "":
			trace |= Default
		case "none":
			return None
		case "perf":
			trace |= Perf
		case "cpu":
			trace |= CPU
		case "mem":
			trace |= Memory
		case "opa":
			trace |= Opa
		case "log":
			trace |= Log
		case "all":
			return All
		}

	}

	return trace
}

// Enabled returns true if one of the provided tracing categories is enabled
func (t Trace) Enabled(categories ...Trace) bool {
	for _, c := range categories {
		if t&c == c {
			return true
		}
	}

	return false
}

// String returns a comma separated list of enabled categories
func (t Trace) String() string {
	if t == None {
		return "none"
	}

	s := ""
	if t.Enabled(Perf) {
		s += "perf,"
	}
	if t.Enabled(CPU) {
		s += "cpu,"
	}
	if t.Enabled(Memory) {
		s += "mem,"
	}
	if t.Enabled(Opa) {
		s += "opa,"
	}
	if t.Enabled(Log) {
		s += "log,"
	}

	return strings.TrimRight(s, ",")
}

// WithTrace returns the context with the given Trace
func WithTrace(ctx context.Context, t Trace) context.Context {
	return context.WithValue(ctx, contextKey, t)
}

// FromContext returns the stored Trace in context or Default
func FromContext(ctx context.Context) Trace {
	if t := ctx.Value(contextKey); t == nil {
		return Default
	} else {
		return t.(Trace)
	}
}
