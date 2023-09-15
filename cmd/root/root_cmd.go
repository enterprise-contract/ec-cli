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

package root

import (
	"context"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	"github.com/enterprise-contract/ec-cli/internal/logging"
)

var cancel context.CancelFunc

func NewRootCmd(verbose bool, quiet bool, debug bool, trace bool, globalTimeout time.Duration) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "ec",
		Short: "Enterprise Contract CLI",

		Long: hd.Doc(`
			Enterprise Contract CLI

			Set of commands to help validate resources with the Enterprise Contract.
		`),

		SilenceUsage: true,

		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			logging.InitLogging(verbose, quiet, debug, trace)

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

	return rootCmd
}
