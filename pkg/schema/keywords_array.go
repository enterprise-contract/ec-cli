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

package schema

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/qri-io/jsonpointer"
	"github.com/qri-io/jsonschema"
)

type uniqueKeys []jsonpointer.Pointer

func newUniqueKeys() jsonschema.Keyword {
	return new(uniqueKeys)
}

func (u *uniqueKeys) Register(uri string, registry *jsonschema.SchemaRegistry) {}

func (u *uniqueKeys) Resolve(pointer jsonpointer.Pointer, uri string) *jsonschema.Schema {
	return nil
}

type element []struct {
	key string
	val any
}

func (u uniqueKeys) el(data any) (element, error) {
	e := make(element, 0, len(u))
	for _, p := range u {
		if v, err := p.Eval(data); err != nil {
			return nil, err
		} else {
			key := p.String()
			if v == nil {
				continue
			}
			e = append(e, struct {
				key string
				val any
			}{key: key, val: v})
		}
	}

	sort.Slice(e, func(i, j int) bool {
		return e[i].key < e[j].key
	})

	return e, nil
}

func (u uniqueKeys) ValidateKeyword(ctx context.Context, currentState *jsonschema.ValidationState, data any) {
	var ary []any
	var ok bool
	if ary, ok = data.([]any); !ok {
		return
	}

	values := make([]string, 0, 5)
	for _, e := range ary {
		if v, err := u.el(e); err != nil {
			currentState.AddError(data, err.Error())
		} else {
			if len(v) == 0 {
				continue
			}

			l := len(values)
			value := fmt.Sprint(v)
			idx := sort.Search(l, func(i int) bool {
				return values[i] >= value
			})
			if idx < l && values[idx] == value {
				j, err := json.Marshal(e)
				if err != nil {
					panic(err)
				}
				currentState.AddError(data, fmt.Sprintf("found non unique value for JSON paths %v: %s", u, j))
			}

			values = append(values, value)
		}
	}
}

func (u *uniqueKeys) UnmarshalJSON(data []byte) error {
	var strs []string
	if err := json.Unmarshal(data, &strs); err != nil {
		return err
	}

	pointers := make([]jsonpointer.Pointer, 0, len(strs))
	for _, str := range strs {
		p, err := jsonpointer.Parse(str)
		if err != nil {
			return err
		}

		pointers = append(pointers, p)
	}

	*u = uniqueKeys(pointers)
	return nil
}

func (u uniqueKeys) MarshalJSON() ([]byte, error) {
	strs := make([]string, 0, len(u))
	for _, p := range u {
		strs = append(strs, p.String())
	}

	return json.Marshal(strs)
}
