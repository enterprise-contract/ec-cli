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

	hd "github.com/MakeNowJust/heredoc"
	"github.com/hashicorp/go-multierror"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/hacbs-contract/ec-cli/internal/format"
	"github.com/hacbs-contract/ec-cli/internal/output"
	"github.com/hacbs-contract/ec-cli/internal/pipeline"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
)

type pipelineValidationFn func(context.Context, afero.Fs, string, []source.PolicySource) (*output.Output, error)

func validatePipelineCmd(validate pipelineValidationFn) *cobra.Command {
	var data = struct {
		filePaths  []string
		policyURLs []string
		dataURLs   []string
		output     []string
	}{
		filePaths:  []string{},
		policyURLs: []string{"oci::quay.io/hacbs-contract/ec-pipeline-policy:latest"},
		dataURLs:   []string{"git::https://github.com/hacbs-contract/ec-policies.git//data"},
		output:     []string{"json"},
	}
	cmd := &cobra.Command{
		Use:   "pipeline",
		Short: "Validate Pipeline conformance with the Enterprise Contract",

		Long: hd.Doc(`
			Validate Pipeline conformance with the Enterprise Contract

			Validate Tekton Pipeline definition files conforms to the rego policies
			defined in the given policy repository.
		`),

		Example: hd.Doc(`
			Validate multiple Pipeline definition files via comma-separated value:

			  ec validate pipeline --pipeline-file </path/to/pipeline/file>,</path/to/other/pipeline/file>

			Validate multiple Pipeline definition files by repeating --pipeline-file:

			  ec validate pipeline --pipeline-file </path/to/pipeline/file> --pipeline-file /path/to/other-pipeline.file

			Specify different policy and data sources:

			  ec validate pipeline --pipeline-file </path/to/pipeline/file> \
				--policy git::https://github.com/hacbs-contract/ec-policies//policy/lib \
				--policy git::https://github.com/hacbs-contract/ec-policies//policy/pipeline \
				--data git::https://github.com/hacbs-contract/ec-policies//data
		`),

		RunE: func(cmd *cobra.Command, args []string) error {
			var allErrors error
			report := pipeline.Report{}
			for i := range data.filePaths {
				fpath := data.filePaths[i]
				var sources []source.PolicySource
				for _, url := range data.policyURLs {
					sources = append(sources, &source.PolicyUrl{Url: url, Kind: source.PolicyKind})
				}
				for _, url := range data.dataURLs {
					sources = append(sources, &source.PolicyUrl{Url: url, Kind: source.DataKind})
				}
				ctx := cmd.Context()
				if o, err := validate(ctx, fs(ctx), fpath, sources); err != nil {
					allErrors = multierror.Append(allErrors, err)
				} else {
					report.Add(*o)
				}
			}
			p := format.NewTargetParser(pipeline.JSONReport, cmd.OutOrStdout(), fs(cmd.Context()))
			for _, target := range data.output {
				if err := report.Write(target, p); err != nil {
					allErrors = multierror.Append(allErrors, err)
				}
			}
			if allErrors != nil {
				return allErrors
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&data.filePaths, "pipeline-file", "p", data.filePaths,
		"path to pipeline definition YAML/JSON file (required)")

	cmd.Flags().StringSliceVar(&data.policyURLs, "policy", data.policyURLs,
		"url for policies, go-getter style. May be used multiple times")

	cmd.Flags().StringSliceVar(&data.dataURLs, "data", data.dataURLs,
		"url for policy data, go-getter style. May be used multiple times")

	cmd.Flags().StringSliceVarP(&data.output, "output", "o", data.output, hd.Doc(`
		write output to a file in a specific format, e.g. yaml=/tmp/output.yaml. Use empty string
		path for stdout, e.g. yaml. May be used multiple times. Possible formats are json and yaml
	`))

	if err := cmd.MarkFlagRequired("pipeline-file"); err != nil {
		panic(err)
	}

	return cmd
}
