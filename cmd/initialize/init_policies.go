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

// Define the `ec init-policies` command
package initialize

import (
	"fmt"
	"path/filepath"

	hd "github.com/MakeNowJust/heredoc"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/enterprise-contract/ec-cli/internal/utils"
)

func initPoliciesCmd() *cobra.Command {
	var destDir string

	cmd := &cobra.Command{
		Use:   "policies --dest-dir <directory-url>",
		Short: "Initialize a directory with minimal EC scaffolding",

		Long: hd.Doc(`
			This command creates the necessary files for a minimal EC policy setup in the
			specified destination directory.

			More information about authoring policies is available in the EC documentation:
			https://enterprisecontract.dev/docs/ec-policies/authoring.html
		`),

		Example: hd.Doc(`
			Initialize the "my-policy" directory with minimal EC policy scaffolding:

			  ec init policies --dest-dir my-policy
		`),

		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			fs := utils.FS(ctx)
			workDir := destDir
			err := fs.MkdirAll(workDir, 0755)
			if err != nil {
				log.Debug("Failed to create policy directory!")
				return err
			}
			policyPath := filepath.Join(workDir, "sample.rego")
			file, err := fs.Create(policyPath)
			if err != nil {
				log.Debug("Failed to create sample policy!")
				return err
			}
			defer file.Close()
			fmt.Fprintf(file, "%s", hd.Doc(`
				# Simplest never-failing policy
				package policy.release.my_package

				# METADATA
				# title: Allow rule
				# description: This rule will never fail
				# custom:
				#   short_name: acceptor
				#   failure_msg: Always succeeds
				#   solution: Easy
				#   collections:
				#   - A
				deny[result] {
					false
					result := "Never denies"
				}
			`))

			return nil
		},
	}

	cmd.Flags().StringVarP(&destDir, "dest-dir", "d", "", "Directory to use when creating EC policy scaffolding")
	if err := cmd.MarkFlagRequired("dest-dir"); err != nil {
		panic(err)
	}

	return cmd
}
