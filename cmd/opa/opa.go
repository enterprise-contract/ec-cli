// Copyright The Enterprise Contract Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
package opa

import (
	"github.com/open-policy-agent/opa/cmd"
	"github.com/spf13/cobra"

	_ "github.com/enterprise-contract/ec-cli/internal/rego" // imports EC OPA builtins
	"github.com/enterprise-contract/ec-cli/internal/rego/testing"
)

var OPACmd *cobra.Command

func init() {
	OPACmd = cmd.RootCommand
	OPACmd.Use = "opa"
	OPACmd.Short = OPACmd.Short + " (embedded)"

	mockingSupport()
}

func mockingSupport() {
	test, _, err := OPACmd.Find([]string{"test"})
	if err != nil {
		panic(err)
	}

	orig := test.PreRunE
	test.PreRunE = func(cmd *cobra.Command, args []string) error {
		if err := orig(cmd, args); err != nil {
			return err
		}

		testing.RegisterMockSupport()

		return nil
	}
}
