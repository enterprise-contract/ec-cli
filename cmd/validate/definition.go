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

package validate

import (
	"context"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"

	"github.com/hacbs-contract/ec-cli/internal/definition"
	"github.com/hacbs-contract/ec-cli/internal/format"
	"github.com/hacbs-contract/ec-cli/internal/output"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
	"github.com/hacbs-contract/ec-cli/internal/utils"
)

type definitionValidationFn func(context.Context, string, []source.PolicySource, []string) (*output.Output, error)

func validateDefinitionCmd(validate definitionValidationFn) *cobra.Command {
	var data = struct {
		filePaths  []string
		policyURLs []string
		dataURLs   []string
		output     []string
		namespaces []string
	}{
		filePaths:  []string{},
		policyURLs: []string{"oci::quay.io/hacbs-contract/ec-pipeline-policy:latest"},
		dataURLs:   []string{"git::https://github.com/hacbs-contract/ec-policies.git//data"},
		output:     []string{"json"},
		namespaces: []string{},
	}
	cmd := &cobra.Command{
		Use:   "definition",
		Short: "Validate definition file conformance with the Enterprise Contract",

		Long: hd.Doc(`
			Validate definition file conformance with the Enterprise Contract

			Validate Kubernetes definition files conforms to the rego policies
			defined in the given policy repository.
		`),

		Example: hd.Doc(`
			Validate multiple definition files via comma-separated value:

			  ec validate definition --file </path/to/file>,</path/to/other/file>

			Validate multiple definition files by repeating --file:

			  ec validate definition --file </path/to/file> --file /path/to/other.file

			Specify --file as JSON

			  ec validate definition --file '{"Kind": "Task"}'

			Specify different policy and data sources:

			  ec validate definition --file </path/to/pipeline/file> \
				--policy git::https://github.com/hacbs-contract/ec-policies//policy/lib \
				--policy git::https://github.com/hacbs-contract/ec-policies//policy/pipeline \
				--data git::https://github.com/hacbs-contract/ec-policies//data
		`),

		RunE: func(cmd *cobra.Command, args []string) error {
			var allErrors error
			report := definition.Report{}
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
				if o, err := validate(ctx, fpath, sources, data.namespaces); err != nil {
					allErrors = multierror.Append(allErrors, err)
				} else {
					report.Add(*o)
				}
			}
			p := format.NewTargetParser(definition.JSONReport, cmd.OutOrStdout(), utils.FS(cmd.Context()))
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

	cmd.Flags().StringArrayVarP(&data.filePaths, "file", "f", data.filePaths,
		"path to definition YAML/JSON file (required)")

	cmd.Flags().StringSliceVar(&data.policyURLs, "policy", data.policyURLs,
		"url for policies, go-getter style. May be used multiple times")

	cmd.Flags().StringSliceVar(&data.dataURLs, "data", data.dataURLs,
		"url for policy data, go-getter style. May be used multiple times")

	cmd.Flags().StringSliceVarP(&data.output, "output", "o", data.output, hd.Doc(`
		write output to a file in a specific format, e.g. yaml=/tmp/output.yaml. Use empty string
		path for stdout, e.g. yaml. May be used multiple times. Possible formats are json and yaml
	`))
	cmd.Flags().StringSliceVar(&data.namespaces, "namespace", data.namespaces,
		"the namespace containing the policy to run. May be used multiple times")

	if err := cmd.MarkFlagRequired("file"); err != nil {
		panic(err)
	}

	return cmd
}
