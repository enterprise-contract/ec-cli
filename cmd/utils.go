// Copyright 2022 Red Hat, Inc.
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

package cmd

import (
	"errors"
	"fmt"
	"strings"
)

// Cobra and pflag don't really have a native way of specifying a list of choices for
// the values of a flag. The most popular solution is to create a custom type which
// implements the required logic in a compatible interface, plag.Value. The code below
// is inspired by: https://github.com/spf13/pflag/issues/236#issuecomment-931600452
type stringEnum struct {
	Allowed []string
	Value   string
}

func newFlagEnum(allowed []string) (*stringEnum, error) {
	if len(allowed) == 0 {
		return nil, errors.New("list of allowed values must not be empty")
	}
	return &stringEnum{
		Allowed: allowed,
		Value:   allowed[0],
	}, nil
}

func (a *stringEnum) String() string {
	return a.Value
}

func (a *stringEnum) Set(value string) error {
	allowed := false
	for _, opt := range a.Allowed {
		if opt == value {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("%q is not one of the allowed values: %s", value, a.AllowedPretty())
	}
	a.Value = value
	return nil
}

func (a *stringEnum) Type() string {
	return "string"
}

func (a *stringEnum) AllowedPretty() string {
	return strings.Join(a.Allowed, ", ")
}
