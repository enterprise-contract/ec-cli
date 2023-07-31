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

package validate

import (
	"context"
	"errors"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"

	"github.com/enterprise-contract/ec-cli/internal/definition"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/format"
	"github.com/enterprise-contract/ec-cli/internal/output"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

type definitionValidationFn func(context.Context, string, []source.PolicySource, []string) (*output.Output, error)

func validateDefinitionCmd(validate definitionValidationFn) *cobra.Command {
	var data = struct {
		filePaths  []string
		policyURLs []string
		dataURLs   []string
		output     []string
		namespaces []string
		strict     bool
	}{
		filePaths:  []string{},
		policyURLs: []string{"oci::quay.io/hacbs-contract/ec-pipeline-policy:latest"},
		dataURLs:   []string{"git::https://github.com/enterprise-contract/ec-policies.git//data"},
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
				--policy git::https://github.com/enterprise-contract/ec-policies//policy/lib \
				--policy git::https://github.com/enterprise-contract/ec-policies//policy/pipeline \
				--data git::https://github.com/enterprise-contract/ec-policies//data
		`),

		RunE: func(cmd *cobra.Command, args []string) error {
			var allErrors error
			report := definition.NewReport()
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
				if out, err := validate(ctx, fpath, sources, data.namespaces); err != nil {
					allErrors = multierror.Append(allErrors, err)
				} else {
					showSuccesses, _ := cmd.Flags().GetBool("show-successes")
					if !showSuccesses {
						for i := range out.PolicyCheck {
							out.PolicyCheck[i].Successes = []evaluator.Result{}
						}

					}
					report.Add(*out)
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
			if data.strict && !report.Success {
				return errors.New("success criteria not met")
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
	cmd.Flags().BoolVarP(&data.strict, "strict", "s", data.strict,
		"return non-zero status on non-successful validation")

	if err := cmd.MarkFlagRequired("file"); err != nil {
		panic(err)
	}

	return cmd
}
