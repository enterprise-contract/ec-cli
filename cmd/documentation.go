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
	"os"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

func documentationCmd() *cobra.Command {
	var data struct {
		DocsDir string
	}
	cmd := &cobra.Command{
		Use:   "docs",
		Short: "Generate documentation",
		Long: `Generates the documentation in multiple formats.
    Specify the target directory by adding the --docs-dir argument.`,
		Example: `
    ec docs
    ec docs --docs-dir /some/other/location
    `,
		RunE: func(cmd *cobra.Command, args []string) error {
			var errs error
			mdPath := data.DocsDir + "/md"
			manPath := data.DocsDir + "/man"
			rstPath := data.DocsDir + "/rst"
			paths := []string{mdPath, manPath, rstPath}

			// Create the target paths
			for _, p := range paths {
				if err := os.MkdirAll(p, os.ModePerm); err != nil {
					errs = multierror.Append(errs, err)
					continue
				}
			}

			// Markdown
			if err := doc.GenMarkdownTree(rootCmd, mdPath); err != nil {
				errs = multierror.Append(errs, err)
			}

			// Man pages
			if err := doc.GenManTree(rootCmd, nil, manPath); err != nil {
				errs = multierror.Append(errs, err)
			}

			// ReStructuredText
			if err := doc.GenReSTTree(rootCmd, rstPath); err != nil {
				errs = multierror.Append(errs, err)
			}

			if errs != nil {
				return errs
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&data.DocsDir, "docs-dir", "docs", "Target directory for the generated documentation.")
	return cmd
}

func init() {
	docs := documentationCmd()
	// Hide the default footer
	rootCmd.DisableAutoGenTag = true
	rootCmd.AddCommand(docs)
}
