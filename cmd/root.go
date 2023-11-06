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

package cmd

import (
	"context"
	"os"

	"github.com/enterprise-contract/ec-cli/cmd/fetch"
	"github.com/enterprise-contract/ec-cli/cmd/initialize"
	"github.com/enterprise-contract/ec-cli/cmd/inspect"
	"github.com/enterprise-contract/ec-cli/cmd/opa"
	"github.com/enterprise-contract/ec-cli/cmd/root"
	"github.com/enterprise-contract/ec-cli/cmd/test"
	"github.com/enterprise-contract/ec-cli/cmd/track"
	"github.com/enterprise-contract/ec-cli/cmd/validate"
	"github.com/enterprise-contract/ec-cli/cmd/version"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = root.NewRootCmd()

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.ExecuteContext(context.Background()); err != nil {
		os.Exit(1)
	}
}

func init() {
	RootCmd.AddCommand(fetch.FetchCmd)
	RootCmd.AddCommand(initialize.InitCmd)
	RootCmd.AddCommand(inspect.InspectCmd)
	RootCmd.AddCommand(track.TrackCmd)
	RootCmd.AddCommand(validate.ValidateCmd)
	RootCmd.AddCommand(version.VersionCmd)
	RootCmd.AddCommand(opa.OPACmd)
	if utils.Experimental() {
		RootCmd.AddCommand(test.TestCmd)
	}
}
