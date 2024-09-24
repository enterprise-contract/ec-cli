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

package http

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

type tracingRoundTripper struct {
	base http.RoundTripper
	log  *log.Logger
}

func NewTracingRoundTripper(transport http.RoundTripper) http.RoundTripper {
	return NewTracingRoundTripperWithLogger(transport, log.StandardLogger())
}

func NewTracingRoundTripperWithLogger(transport http.RoundTripper, l *log.Logger) http.RoundTripper {
	return &tracingRoundTripper{transport, l}
}

func (t *tracingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	t.log.Tracef("START: %s %s", req.Method, req.URL)
	resp, err := t.base.RoundTrip(req)

	t.log.Tracef("DONE: %s %s (%d)", req.Method, req.URL, resp.ContentLength)

	return resp, err
}
