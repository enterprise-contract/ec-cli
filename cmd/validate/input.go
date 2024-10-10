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
	"fmt"
	"runtime/trace"
	"sort"
	"strings"
	"sync"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	"github.com/enterprise-contract/ec-cli/internal/applicationsnapshot"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/format"
	"github.com/enterprise-contract/ec-cli/internal/input"
	"github.com/enterprise-contract/ec-cli/internal/output"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/utils"
	validate_utils "github.com/enterprise-contract/ec-cli/internal/validate"
)

type InputValidationFunc func(context.Context, string, policy.Policy, bool) (*output.Output, error)

func validateInputCmd(validate InputValidationFunc) *cobra.Command {
	data := struct {
		effectiveTime       string
		filePaths           []string
		info                bool
		namespaces          []string
		output              []string
		policy              policy.Policy
		policyConfiguration string
		strict              bool
	}{
		strict: true,
	}
	cmd := &cobra.Command{
		Use:   "input",
		Short: "Validate arbitrary JSON or yaml file input conformance with the Enterprise Contract",
		Long: hd.Doc(`
			Validate conformance of arbitrary JSON or yaml file input with the Enterprise Contract

			For each file, validation is performed to determine if the file conforms to rego policies
			defined in the the EnterpriseContractPolicy.
			`),
		Example: hd.Doc(`
			Use an EnterpriseContractPolicy spec from a local YAML file to validate a single file
			ec validate input --file /path/to/file.json --policy my-policy.yaml

			Use an EnterpriseContractPolicy spec from a local YAML file to validate multiple files
			The file flag can be repeated for multiple input files.
			ec validate input --file /path/to/file.yaml --file /path/to/file2.yaml --policy my-policy.yaml

			Use an EnterpriseContractPolicy spec from a local YAML file to validate multiple files
			The file flag can take a comma separated series of files.
			ec validate input --file="/path/to/file.json,/path/to/file2.json" --policy my-policy.yaml

			Use a git url for the policy configuration. In the first example there should be a '.ec/policy.yaml'
			or a 'policy.yaml' inside a directory called 'default' in the top level of the git repo. In the second
			example there should be a '.ec/policy.yaml' or a 'policy.yaml' file in the top level
			of the git repo. For git repos not hosted on 'github.com' or 'gitlab.com', prefix the url with
			'git::'. For the policy configuration files you can use json instead of yaml if you prefer.

			  ec validate input --file /path/to/file.json --policy github.com/user/repo//default?ref=main

			  ec validate input --file /path/to/file.yaml --policy github.com/user/repo

`),
		PreRunE: func(cmd *cobra.Command, args []string) (allErrors error) {
			ctx := cmd.Context()

			policyConfiguration, err := validate_utils.GetPolicyConfig(ctx, data.policyConfiguration)
			if err != nil {
				allErrors = errors.Join(allErrors, err)
				return
			}
			data.policyConfiguration = policyConfiguration

			if p, err := policy.NewInputPolicy(cmd.Context(), data.policyConfiguration, data.effectiveTime); err != nil {
				allErrors = errors.Join(allErrors, err)
			} else {
				data.policy = p
			}
			return
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if trace.IsEnabled() {
				ctx, task := trace.NewTask(cmd.Context(), "ec:validate-inputs")
				cmd.SetContext(ctx)
				defer task.End()
			}

			type result struct {
				err         error
				input       input.Input
				data        []evaluator.Data
				policyInput []byte
			}

			ch := make(chan result, len(data.filePaths))

			var lock sync.WaitGroup

			showSuccesses, _ := cmd.Flags().GetBool("show-successes")

			for _, f := range data.filePaths {
				lock.Add(1)
				go func(fpath string) {
					ctx := cmd.Context()
					var task *trace.Task
					if trace.IsEnabled() {
						ctx, task = trace.NewTask(ctx, "ec:validate-input")
					}

					defer lock.Done()

					out, err := validate(ctx, fpath, data.policy, data.info)
					res := result{
						err: err,
						input: input.Input{
							FilePath: fpath,
							Success:  err == nil,
						},
					}
					// Skip on err to not panic. Error is return on routine completion.
					if err == nil {
						res.input.Violations = out.Violations()
						res.input.Warnings = out.Warnings()

						successes := out.Successes()
						res.input.SuccessCount = len(successes)
						if showSuccesses {
							res.input.Successes = successes
						}
						res.data = out.Data
					}
					res.input.Success = err == nil && len(res.input.Violations) == 0

					if task != nil {
						task.End()
					}
					ch <- res
				}(f)
			}

			lock.Wait()
			close(ch)

			var inputs []input.Input
			var manyData [][]evaluator.Data
			var manyPolicyInput [][]byte
			var allErrors error = nil

			for r := range ch {
				if r.err != nil {
					e := fmt.Errorf("error validating file %s: %w", r.input.FilePath, r.err)
					allErrors = errors.Join(allErrors, e)
				} else {
					inputs = append(inputs, r.input)
					manyData = append(manyData, r.data)
					manyPolicyInput = append(manyPolicyInput, r.policyInput)
				}
			}
			if allErrors != nil {
				return allErrors
			}

			// Ensure some consistency in output.
			sort.Slice(inputs, func(i, j int) bool {
				return inputs[i].FilePath > inputs[j].FilePath
			})

			report, err := input.NewReport(inputs, data.policy, manyData, manyPolicyInput)
			if err != nil {
				return err
			}

			p := format.NewTargetParser(input.JSON, format.Options{ShowSuccesses: showSuccesses}, cmd.OutOrStdout(), utils.FS(cmd.Context()))
			if err := report.WriteAll(data.output, p); err != nil {
				return err
			}

			if data.strict && !report.Success {
				return errors.New("success criteria not met")
			}

			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&data.filePaths, "file", "f", data.filePaths, "path to input YAML/JSON file (required)")

	cmd.Flags().StringVarP(&data.policyConfiguration, "policy", "p", data.policyConfiguration, hd.Doc(`
		Policy configuration as:
		* file (policy.yaml)
		* git reference (github.com/user/repo//default?ref=main), or
		* inline JSON ('{sources: {...}}')")`))

	validOutputFormats := applicationsnapshot.OutputFormats
	cmd.Flags().StringSliceVarP(&data.output, "output", "o", data.output, hd.Doc(`
		Write output to a file in a specific format, e.g. yaml=/tmp/output.yaml. Use empty string
		path for stdout, e.g. yaml. May be used multiple times. Possible formats are:
		`+strings.Join(validOutputFormats, ", ")+`. In following format and file path
		additional options can be provided in key=value form following the question
		mark (?) sign, for example: --output text=output.txt?show-successes=false
	`))

	cmd.Flags().BoolVarP(&data.strict, "strict", "s", data.strict,
		"Return non-zero status on non-successful validation")

	cmd.Flags().StringVar(&data.effectiveTime, "effective-time", policy.Now, hd.Doc(`
		Run policy checks with the provided time. Useful for testing rules with
		effective dates in the future. The value can be "now" (default) - for
		current time, or a RFC3339 formatted value, e.g. 2022-11-18T00:00:00Z.`))

	cmd.Flags().BoolVar(&data.info, "info", data.info, hd.Doc(`
		Include additional information on the failures. For instance for policy
		violations, include the title and the description of the failed policy
		rule.`))

	if err := cmd.MarkFlagRequired("file"); err != nil {
		panic(err)
	}

	if err := cmd.MarkFlagRequired("policy"); err != nil {
		panic(err)
	}

	return cmd
}
