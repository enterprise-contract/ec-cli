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

package http

import (
	"net/http"
	"runtime/trace"
)

type tracingRoundTripper struct {
	base http.RoundTripper
}

func NewTracingRoundTripper(transport http.RoundTripper) http.RoundTripper {
	return NewTracingRoundTripperWithLogger(transport)
}

func NewTracingRoundTripperWithLogger(transport http.RoundTripper) http.RoundTripper {
	return &tracingRoundTripper{transport}
}

func (t *tracingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if trace.IsEnabled() {
		region := trace.StartRegion(ctx, "http-request")
		defer region.End()

		trace.Logf(ctx, "http", "method=%q", req.Method)
		trace.Logf(ctx, "http", "url=%q", req.URL.String())
	}

	resp, err := t.base.RoundTrip(req)

	if trace.IsEnabled() {
		trace.Logf(ctx, "http", "received=%d", resp.ContentLength)
	}

	return resp, err
}
