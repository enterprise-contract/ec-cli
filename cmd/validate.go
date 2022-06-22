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
	"github.com/hacbs-contract/ec-cli/internal/pipeline"
	"github.com/spf13/cobra"
)

func validateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Provides validation of various object",
		Long:  "TODO",
	}
	return cmd
}

func validatePipelineCmd() *cobra.Command {
	var data = struct {
		FilePaths         []string
		PolicyRepo        string
		PolicyDir         string
		Ref               string
		ConftestNamespace string
	}{
		FilePaths:         []string{},
		PolicyRepo:        "https://github.com/hacbs-contract/ec-policies.git",
		PolicyDir:         "policy",
		ConftestNamespace: "pipeline.main",
		Ref:               "main",
	}
	cmd := &cobra.Command{
		Use:   "pipeline",
		Short: "Validates a pipeline file",
		Long: "This command validates one or more Tekton Pipeline definition files.Definition\n" +
			"files can be either YAML or JSON format. Multiple definition files can be\n" +
			"specified by providing a comma seperated list, ensuring no spaces, or by\n" +
			"repeating the '--pipeline-file' flag.\n\n" +
			"The git repository, from which the policies should be checked out, can be\n" +
			"specified as can a specific branch. If policies are not contained in the\n" +
			"standard 'policy' subdirectory, the appropriate subdirectory within the\n" +
			"repository can be specified.\n\n" +
			"The namespace of policies can be specified as well, by use of the\n" +
			"'--namespace' flag.",
		Example: "ec validate pipeline --pipeline-file /path/to/pipeline.file\n" +
			"ec validate pipeline --pipeline-file /path/to/pipeline.file,/path/to/other-pipeline.file\n" +
			"ec validate pipeline --pipeline-file /path/to/pipeline.file --pipeline-file /path/to/other-pipeline.file\n" +
			"ec validate pipeline --pipeline-file /path/to/pipeline.file --policy-repo https://example.com/user/repo.git\n" +
			"ec validate pipeline --pipeline-file /path/to/pipeline.file --branch foo\n" +
			"ec validate pipeline --pipeline-file /path/to/pipeline.file --policy-dir policies\n" +
			"ec validate pipeline --pipeline-file /path/to/pipeline.file --namespace pipeline.basic\n" +
			"",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			for i := range data.FilePaths {
				fpath := data.FilePaths[i]
				policySource := pipeline.PolicyRepo{
					PolicyDir: data.PolicyDir,
					RepoURL:   data.PolicyRepo,
					RepoRef:   data.Ref,
				}
				err = pipeline.ValidatePipeline(cmd.Context(), fpath, policySource, data.ConftestNamespace)
			}
			if err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&data.FilePaths, "pipeline-file", "p", data.FilePaths, "REQUIRED - The path to the pipeline file to validate. Can be JSON or YAML")
	cmd.Flags().StringVar(&data.PolicyDir, "policy-dir", data.PolicyDir, "Subdirectory containing policies, if not in default 'policy' subdirectory.")
	cmd.Flags().StringVar(&data.PolicyRepo, "policy-repo", data.PolicyRepo, "Git repo containing policies.")
	cmd.Flags().StringVar(&data.Ref, "branch", data.Ref, "Branch to use.")
	cmd.Flags().StringVar(&data.ConftestNamespace, "namespace", data.ConftestNamespace, "Namespace of policy to validate against")
	_ = cmd.MarkFlagRequired("pipeline-file")
	return cmd
}

func init() {
	validate := validateCmd()
	validate.AddCommand(validatePipelineCmd())
	rootCmd.AddCommand(validate)
}
