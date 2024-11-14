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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package mutate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMutatesStructFields(t *testing.T) {
	s := struct {
		some string
	}{
		"hello",
	}

	m := Value(&s.some)

	assert.Equal(t, "hello", s.some)
	assert.Equal(t, "hello", m.Value())

	m.Set("hi")
	assert.Equal(t, "hi", s.some)
	assert.Equal(t, "hi", m.Value())
}

func TestMutatesSliceItems(t *testing.T) {
	s := []string{
		"hello",
		"world",
	}

	m := Slice(s, 1)

	assert.Equal(t, []string{"hello", "world"}, s)
	assert.Equal(t, "world", m.Value())

	m.Set("universe")
	assert.Equal(t, []string{"hello", "universe"}, s)
	assert.Equal(t, "universe", m.Value())
}

func TestEquality(t *testing.T) {
	x := "value"

	assert.Equal(t, Value(&x), Value(&x))
	assert.Equal(t, Value(&x), Const("value"))
}
