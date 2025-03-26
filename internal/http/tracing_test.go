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
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type transport struct {
	mock.Mock
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	args := t.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

func TestDelegation(t *testing.T) {
	delegate := &transport{}
	tracing := NewTracingRoundTripper(delegate)

	u, err := url.Parse("http://example.com")
	require.NoError(t, err)

	req := &http.Request{
		Method: "GET",
		URL:    u,
	}
	res := &http.Response{
		ContentLength: 42,
	}
	delegate.On("RoundTrip", req).Return(res, nil)
	r, err := tracing.RoundTrip(req)
	assert.Same(t, res, r)
	assert.Nil(t, err)

	mock.AssertExpectationsForObjects(t, delegate)
}
