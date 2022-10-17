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

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"

	"github.com/hacbs-contract/ec-cli/internal/output"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
)

type pipelineValidationFn func(context.Context, string, source.PolicyUrl, string) (*output.Output, error)

func validatePipelineCmd(validate pipelineValidationFn) *cobra.Command {
	var data = struct {
		FilePaths         []string
		PolicyUrl         string
		Ref               string
		ConftestNamespace string
	}{
		FilePaths:         []string{},
		PolicyUrl:         "git::https://github.com/hacbs-contract/ec-policies.git//policy",
		ConftestNamespace: "pipeline.main",
		Ref:               "main",
	}
	cmd := &cobra.Command{
		Use:   "pipeline",
		Short: "Validate Pipeline conformance with the Enterprise Contract",
		Long: `Validate Pipeline conformance with the Enterprise Contract

Validate Tekton Pipeline definition files conforms to the rego policies
defined in the given policy repository.`,
		Example: `Validate multiple Pipeline definition files via comma-separated value:

  ec validate pipeline --pipeline-file </path/to/pipeline/file>,</path/to/other/pipeline/file>

Validate multiple Pipeline definition files by repeating --pipeline-file:

  ec validate pipeline --pipeline-file </path/to/pipeline/file> --pipeline-file /path/to/other-pipeline.file

Sepcify a different location for the policies:

  ec validate pipeline --pipeline-file </path/to/pipeline/file> \
    --policy git::https://example.com/user/repo.git//policy?ref=main --namespace pipeline.basic`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			var outputs output.Outputs
			for i := range data.FilePaths {
				fpath := data.FilePaths[i]
				policySource := source.PolicyUrl(data.PolicyUrl)
				if o, e := validate(cmd.Context(), fpath, policySource, data.ConftestNamespace); e != nil {
					err = multierror.Append(err, e)
				} else {
					outputs = append(outputs, o)
				}
			}
			outputs.Print(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&data.FilePaths, "pipeline-file", "p", data.FilePaths,
		"path to pipeline definition YAML/JSON file (required)")
	cmd.Flags().StringVar(&data.PolicyUrl, "policy", data.PolicyUrl,
		"git repo containing policies")
	cmd.Flags().StringVar(&data.ConftestNamespace, "namespace", data.ConftestNamespace,
		"rego namespace within policy repo")

	if err := cmd.MarkFlagRequired("pipeline-file"); err != nil {
		panic(err)
	}
	return cmd
}
