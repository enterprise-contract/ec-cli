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
	"sort"
	"sync"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/hashicorp/go-multierror"
	app "github.com/redhat-appstudio/application-api/api/v1alpha1"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/spf13/cobra"

	"github.com/enterprise-contract/ec-cli/internal/applicationsnapshot"
	"github.com/enterprise-contract/ec-cli/internal/evaluator"
	"github.com/enterprise-contract/ec-cli/internal/format"
	"github.com/enterprise-contract/ec-cli/internal/output"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/utils"
	validate_utils "github.com/enterprise-contract/ec-cli/internal/validate"
)

type imageValidationFunc func(context.Context, app.SnapshotComponent, policy.Policy, bool) (*output.Output, error)

func validateImageCmd(validate imageValidationFunc) *cobra.Command {
	var data = struct {
		certificateIdentity         string
		certificateIdentityRegExp   string
		certificateOIDCIssuer       string
		certificateOIDCIssuerRegExp string
		effectiveTime               string
		filePath                    string // Deprecated: images replaced this
		imageRef                    string
		info                        bool
		input                       string // Deprecated: images replaced this
		ignoreRekor                 bool
		output                      []string
		outputFile                  string
		policy                      policy.Policy
		policyConfiguration         string
		publicKey                   string
		rekorURL                    string
		snapshot                    string
		spec                        *app.SnapshotSpec
		strict                      bool
		images                      string
		intent                      string
	}{
		strict: true,
	}
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Validate conformance of container images with the Enterprise Contract",

		Long: hd.Doc(`
			Validate conformance of container images with the Enterprise Contract

			For each image, validation is performed in stages to determine if the image
			conforms to the Enterprise Contract.

			The first validation stage determines if an image has been signed, and the
			signature matches the provided public key. This is akin to the "cosign verify"
			command.

			The second validation stage determines if one or more attestations exist, and
			those attestations have been signed matching the provided public key, similarly
			to the "cosign verify-attestation" command. This stage temporarily stores the
			attestations for usage in the next stage.

			The final stage verifies the attestations conform to rego policies defined in
			the EnterpriseContractPolicy.

			Validation advances each stage as much as possible for each image in order to
			capture all issues in a single execution.
		`),

		Example: hd.Doc(`
			Validate single image with the policy defined in the EnterpriseContractPolicy
			custom resource named "default" in the enterprise-contract-service Kubernetes
			namespace:

			  ec validate image --image registry/name:tag

			Validate multiple images from an ApplicationSnapshot Spec file:

			  ec validate image --images my-app.yaml

			Validate attestation of images from an inline ApplicationSnapshot Spec:

			  ec validate image --images '{"components":[{"containerImage":"<image url>"}]}'

			Use a different public key than the one from the EnterpriseContractPolicy resource:

			  ec validate image --image registry/name:tag --public-key <path/to/public/key>

			Use a different Rekor URL than the one from the EnterpriseContractPolicy resource:

			  ec validate image --image registry/name:tag --rekor-url https://rekor.example.org

			Return a non-zero status code on validation failure:

			  ec validate image --image registry/name:tag

		  	Return a zero status code even if there are validation failures:

			  ec validate image --image registry/name:tag --strict=false

			Use an EnterpriseContractPolicy resource from the currently active kubernetes context:

			  ec validate image --image registry/name:tag --policy my-policy

			Use an EnterpriseContractPolicy resource from a different namespace:

			  ec validate image --image registry/name:tag --policy my-namespace/my-policy

			Use an inline EnterpriseContractPolicy spec

			  ec validate image --image registry/name:tag --policy '{"publicKey": "<path/to/public/key>"}'

			Use an EnterpriseContractPolicy spec from a local YAML file
			  ec validate image --image registry/name:tag --policy my-policy.yaml

			Use a git url for the policy configuration. In the first example there should be a '.ec/policy.yaml'
			or a 'policy.yaml' inside a directory called 'default' in the top level of the git repo. In the second
			example there should be a '.ec/policy.yaml' or a 'policy.yaml' file in the top level
			of the git repo. For git repos not hosted on 'github.com' or 'gitlab.com', prefix the url with
			'git::'. For the policy configuration files you can use json instead of yaml if you prefer.

			  ec validate image --image registry/name:tag --policy github.com/user/repo//default?ref=main

			  ec validate image --image registry/name:tag --policy github.com/user/repo

			Write output in JSON format to a file

			  ec validate image --image registry/name:tag --output json=<path>

			Write output in YAML format to stdout and in appstudio format to a file

			  ec validate image --image registry/name:tag --output yaml --output appstudio=<path>

			Write the data used in the policy evaluation to a file in YAML format

			  ec validate image --image registry/name:tag --output data=<path>

			Validate a single image with keyless workflow.

			  ec validate image --image registry/name:tag --policy my-policy \
			    --certificate-identity 'https://github.com/user/repo/.github/workflows/push.yaml@refs/heads/main' \
			    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
			    --rekor-url 'https://rekor.sigstore.dev'

			Use a regular expression to match certificate attributes.

			  ec validate image --image registry/name:tag --policy my-policy \
			    --certificate-identity-regexp '^https://github\.com' \
			    --certificate-oidc-issuer-regexp 'githubusercontent' \
			    --rekor-url 'https://rekor.sigstore.dev'
		`),

		PreRunE: func(cmd *cobra.Command, args []string) (allErrors error) {
			ctx := cmd.Context()
			if s, err := applicationsnapshot.DetermineInputSpec(ctx, applicationsnapshot.Input{
				File:     data.filePath,
				JSON:     data.input,
				Image:    data.imageRef,
				Snapshot: data.snapshot,
				Images:   data.images,
			}); err != nil {
				allErrors = multierror.Append(allErrors, err)
			} else {
				data.spec = s
			}

			policyConfiguration, err := validate_utils.GetPolicyConfig(ctx, data.policyConfiguration)
			if err != nil {
				allErrors = multierror.Append(allErrors, err)
				return
			}
			data.policyConfiguration = policyConfiguration

			if p, err := policy.NewPolicy(cmd.Context(), policy.Options{
				EffectiveTime: data.effectiveTime,
				Identity: cosign.Identity{
					Issuer:        data.certificateOIDCIssuer,
					IssuerRegExp:  data.certificateOIDCIssuerRegExp,
					Subject:       data.certificateIdentity,
					SubjectRegExp: data.certificateIdentityRegExp,
				},
				IgnoreRekor: data.ignoreRekor,
				PolicyRef:   data.policyConfiguration,
				PublicKey:   data.publicKey,
				RekorURL:    data.rekorURL,
				Intent:      data.intent,
			}); err != nil {
				allErrors = multierror.Append(allErrors, err)
			} else {
				data.policy = p
			}

			return
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			type result struct {
				err         error
				component   applicationsnapshot.Component
				data        []evaluator.Data
				policyInput []byte
			}

			appComponents := data.spec.Components

			ch := make(chan result, len(appComponents))

			var lock sync.WaitGroup
			for _, c := range appComponents {
				lock.Add(1)
				go func(comp app.SnapshotComponent) {
					defer lock.Done()

					ctx := cmd.Context()
					out, err := validate(ctx, comp, data.policy, data.info)
					res := result{
						err: err,
						component: applicationsnapshot.Component{
							SnapshotComponent: comp,
							Success:           err == nil,
						},
					}

					// Skip on err to not panic. Error is return on routine completion.
					if err == nil {
						res.component.Violations = out.Violations()
						showSuccesses, _ := cmd.Flags().GetBool("show-successes")
						res.component.Warnings = out.Warnings()

						successes := out.Successes()
						res.component.SuccessCount = len(successes)
						if showSuccesses {
							res.component.Successes = successes
						}

						res.component.Signatures = out.Signatures
						res.component.Attestations = out.Attestations
						res.component.ContainerImage = out.ImageURL
						res.data = out.Data
						res.component.Attestations = out.Attestations
						res.policyInput = out.PolicyInput
					}
					res.component.Success = err == nil && len(res.component.Violations) == 0

					ch <- res
				}(c)
			}

			lock.Wait()
			close(ch)

			var components []applicationsnapshot.Component
			var manyData [][]evaluator.Data
			var manyPolicyInput [][]byte
			var allErrors error = nil
			for r := range ch {
				if r.err != nil {
					e := fmt.Errorf("error validating image %s of component %s: %w", r.component.ContainerImage, r.component.Name, r.err)
					allErrors = multierror.Append(allErrors, e)
				} else {
					components = append(components, r.component)
					manyData = append(manyData, r.data)
					manyPolicyInput = append(manyPolicyInput, r.policyInput)
				}
			}
			if allErrors != nil {
				return allErrors
			}

			// Ensure some consistency in output.
			sort.Slice(components, func(i, j int) bool {
				return components[i].ContainerImage > components[j].ContainerImage
			})

			if len(data.outputFile) > 0 {
				data.output = append(data.output, fmt.Sprintf("%s=%s", applicationsnapshot.JSON, data.outputFile))
			}

			report, err := applicationsnapshot.NewReport(data.snapshot, components, data.policy, manyData, manyPolicyInput)
			if err != nil {
				return err
			}
			p := format.NewTargetParser(applicationsnapshot.JSON, cmd.OutOrStdout(), utils.FS(cmd.Context()))
			if err := report.WriteAll(data.output, p); err != nil {
				return err
			}

			if data.strict && !report.Success {
				return errors.New("success criteria not met")
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&data.policyConfiguration, "policy", "p", data.policyConfiguration, hd.Doc(`
		Policy configuration as:
		  * Kubernetes reference ([<namespace>/]<name>)
		  * file (policy.yaml)
		  * git reference (github.com/user/repo//default?ref=main), or
		  * inline JSON ('{sources: {...}, configuration: {...}}')")`))

	cmd.Flags().StringVarP(&data.imageRef, "image", "i", data.imageRef, "OCI image reference")

	cmd.Flags().StringVarP(&data.publicKey, "public-key", "k", data.publicKey,
		"path to the public key. Overrides publicKey from EnterpriseContractPolicy")

	cmd.Flags().StringVarP(&data.rekorURL, "rekor-url", "r", data.rekorURL,
		"Rekor URL. Overrides rekorURL from EnterpriseContractPolicy")

	cmd.Flags().BoolVar(&data.ignoreRekor, "ignore-rekor", data.ignoreRekor,
		"Skip Rekor transparency log checks during validation.")

	cmd.Flags().StringVar(&data.certificateIdentity, "certificate-identity", data.certificateIdentity,
		"URL of the certificate identity for keyless verification")

	cmd.Flags().StringVar(&data.certificateIdentityRegExp, "certificate-identity-regexp", data.certificateIdentityRegExp,
		"Regular expression for the URL of the certificate identity for keyless verification")

	cmd.Flags().StringVar(&data.certificateOIDCIssuer, "certificate-oidc-issuer", data.certificateOIDCIssuer,
		"URL of the certificate OIDC issuer for keyless verification")

	cmd.Flags().StringVar(&data.certificateOIDCIssuerRegExp, "certificate-oidc-issuer-regexp", data.certificateOIDCIssuerRegExp,
		"Regular expresssion for the URL of the certificate OIDC issuer for keyless verification")

	// Deprecated: images replaced this
	cmd.Flags().StringVarP(&data.filePath, "file-path", "f", data.filePath,
		"DEPRECATED - use --images: path to ApplicationSnapshot Spec JSON file")

	// Deprecated: images replaced this
	cmd.Flags().StringVarP(&data.input, "json-input", "j", data.input,
		"DEPRECATED - use --images: JSON representation of an ApplicationSnapshot Spec")

	cmd.Flags().StringVar(&data.images, "images", data.images,
		"path to ApplicationSnapshot Spec JSON file or JSON representation of an ApplicationSnapshot Spec")

	cmd.Flags().StringSliceVar(&data.output, "output", data.output, hd.Doc(`
		write output to a file in a specific format. Use empty string path for stdout.
		May be used multiple times. Possible formats are json, yaml, appstudio, junit,
		summary, data, and policy-input.
	`))

	cmd.Flags().StringVarP(&data.outputFile, "output-file", "o", data.outputFile,
		"[DEPRECATED] write output to a file. Use empty string for stdout, default behavior")

	cmd.Flags().BoolVarP(&data.strict, "strict", "s", data.strict,
		"Return non-zero status on non-successful validation. Defaults to true. Use --strict=false to return a zero status code.")

	cmd.Flags().StringVar(&data.effectiveTime, "effective-time", policy.Now, hd.Doc(`
		Run policy checks with the provided time. Useful for testing rules with
		effective dates in the future. The value can be "now" (default) - for
		current time, "attestation" - for time from the youngest attestation, or
		a RFC3339 formatted value, e.g. 2022-11-18T00:00:00Z.
	`))

	cmd.Flags().StringVar(&data.snapshot, "snapshot", "", hd.Doc(`
		Provide the AppStudio Snapshot as a source of the images to validate, as inline
		JSON of the "spec" or a reference to a Kubernetes object [<namespace>/]<name>`))

	cmd.Flags().BoolVar(&data.info, "info", data.info, hd.Doc(`
		Include additional information on the failures. For instance for policy
		violations, include the title and the description of the failed policy
		rule.`))

	cmd.Flags().StringVar(&data.intent, "intent", data.intent, hd.Doc(`
		Specify the intent of validating an image.
	`))

	if len(data.input) > 0 || len(data.filePath) > 0 || len(data.images) > 0 {
		if err := cmd.MarkFlagRequired("image"); err != nil {
			panic(err)
		}
	}

	return cmd
}
