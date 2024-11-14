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

import "fmt"

type Mut[T any] interface {
	Value() T
	Set(T)
}

type mutableValue[T any] struct {
	v *T
}

func (m *mutableValue[T]) Value() T {
	return *m.v
}

func (m *mutableValue[T]) Set(value T) {
	*m.v = value
}

func (m *mutableValue[T]) String() string {
	return fmt.Sprint("%", *m.v)
}

func Value[T any](value *T) Mut[T] {
	return &mutableValue[T]{value}
}

func Const[T any](value T) Mut[T] {
	return &mutableValue[T]{&value}
}

type mutableSlice[T any] struct {
	s   []T
	idx int
}

func (m *mutableSlice[T]) Value() T {
	return m.s[m.idx]
}

func (m *mutableSlice[T]) Set(value T) {
	m.s[m.idx] = value
}

func Slice[T any](s []T, i int) Mut[T] {
	return &mutableSlice[T]{s, i}
}
