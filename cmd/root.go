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
	"context"
	"os"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	"github.com/enterprise-contract/ec-cli/cmd/fetch"
	"github.com/enterprise-contract/ec-cli/cmd/inspect"
	"github.com/enterprise-contract/ec-cli/cmd/track"
	"github.com/enterprise-contract/ec-cli/cmd/validate"
	"github.com/enterprise-contract/ec-cli/cmd/version"
	"github.com/enterprise-contract/ec-cli/internal/kubernetes"
	"github.com/enterprise-contract/ec-cli/internal/logging"
)

var cancel context.CancelFunc

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "ec",
	Short: "Enterprise Contract CLI",

	Long: hd.Doc(`
		Enterprise Contract CLI

		Set of commands to help validate resources with the Enterprise Contract.
	`),

	SilenceUsage: true,

	PersistentPreRun: func(cmd *cobra.Command, _ []string) {
		logging.InitLogging(verbose, quiet, debug)

		// Create a new context now that flags have been parsed so a custom timeout can be used.
		ctx := cmd.Context()
		ctx, cancel = context.WithTimeout(ctx, globalTimeout)
		cmd.SetContext(ctx)
	},

	PersistentPostRun: func(cmd *cobra.Command, _ []string) {
		if cancel != nil {
			cancel()
		}
	},
}

var quiet bool = false
var verbose bool = false
var debug bool = false
var globalTimeout = 5 * time.Minute

func init() {
	RootCmd.PersistentFlags().BoolVar(&quiet, "quiet", quiet, "less verbose output")
	RootCmd.PersistentFlags().BoolVar(&verbose, "verbose", verbose, "more verbose output")
	RootCmd.PersistentFlags().BoolVar(&debug, "debug", debug, "same as verbose but also show function names and line numbers")
	RootCmd.PersistentFlags().DurationVar(&globalTimeout, "timeout", globalTimeout, "max overall execution duration")
	kubernetes.AddKubeconfigFlag(RootCmd)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.ExecuteContext(context.Background()); err != nil {
		os.Exit(1)
	}
}

func init() {
	RootCmd.AddCommand(fetch.FetchCmd)
	RootCmd.AddCommand(inspect.InspectCmd)
	RootCmd.AddCommand(track.TrackCmd)
	RootCmd.AddCommand(validate.ValidateCmd)
	RootCmd.AddCommand(version.VersionCmd)
}
