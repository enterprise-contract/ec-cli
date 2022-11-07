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

	"github.com/spf13/cobra"

	"github.com/hacbs-contract/ec-cli/internal/kubernetes"
	"github.com/hacbs-contract/ec-cli/internal/logging"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "ec",
	Short: "Enterprise Contract CLI",
	Long: `Enterprise Contract CLI

Set of commands to help validate resources with the Enterprise Contract.`,
	SilenceUsage: true,

	PersistentPreRun: func(cmd *cobra.Command, _ []string) {
		logging.InitLogging(verbose, quiet, debug)
	},
}

var quiet bool = false
var verbose bool = false
var debug bool = false

func init() {
	RootCmd.PersistentFlags().BoolVar(&quiet, "quiet", quiet, "less verbose output")
	RootCmd.PersistentFlags().BoolVar(&verbose, "verbose", verbose, "more verbose output")
	RootCmd.PersistentFlags().BoolVar(&debug, "debug", debug, "same as verbose but also show function names and line numbers")
	kubernetes.AddKubeconfigFlag(RootCmd)
}

const globalTimeout = 5 * time.Minute

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	ctx, cancel := context.WithTimeout(context.Background(), globalTimeout)
	defer cancel()

	err := RootCmd.ExecuteContext(ctx)
	if err != nil {
		os.Exit(1)
	}
}
