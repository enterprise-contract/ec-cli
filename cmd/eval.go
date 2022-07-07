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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/hacbs-contract/ec-cli/internal/applicationsnapshot"
	"github.com/hacbs-contract/ec-cli/internal/image"
	"github.com/hacbs-contract/ec-cli/internal/policy"
	"github.com/hacbs-contract/ec-cli/internal/utils"
	"github.com/hashicorp/go-multierror"
	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	"github.com/spf13/cobra"
)

type imageValidationFn func(ctx context.Context, imageRef, policyConfiguration, publicKey, rekorURL string) (*policy.Output, error)

func init() {
	rootCmd.AddCommand(evalCmd(validateImage))
}

type args struct {
	policyConfiguration string
	imageRef            string
	publicKey           string
	rekorURL            string
	strict              bool
	input               string
	filepath            string
	output              string
	spec                *appstudioshared.ApplicationSnapshotSpec
}

func evalCmd(validate imageValidationFn) *cobra.Command {
	var arguments = args{
		rekorURL: "https://rekor.sigstore.dev/",
	}
	evalCmd := &cobra.Command{
		Use:   "eval",
		Short: "Evaluate enterprise contract",
		Long:  `TODO: description`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			s, err := determineInputSpec(arguments)
			if err != nil {
				return err
			}

			arguments.spec = s

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			type result struct {
				err       error
				component applicationsnapshot.Component
			}

			appComponents := arguments.spec.Components

			ch := make(chan result, len(appComponents))

			var lock sync.WaitGroup
			for _, c := range appComponents {
				lock.Add(1)
				go func(comp appstudioshared.ApplicationSnapshotComponent) {
					defer lock.Done()

					out, err := validate(cmd.Context(), comp.ContainerImage, arguments.policyConfiguration, arguments.publicKey, arguments.rekorURL)
					res := result{
						err: err,
						component: applicationsnapshot.Component{
							ApplicationSnapshotComponent: appstudioshared.ApplicationSnapshotComponent{
								Name:           comp.Name,
								ContainerImage: comp.ContainerImage,
							},
							Success: err == nil,
						},
					}

					// Skip on err to not panic. Error is return on routine completion.
					if err == nil {
						res.component.Violations = out.Violations()
					}

					res.component.Success = err == nil && len(res.component.Violations) == 0

					ch <- res
				}(c)
			}

			lock.Wait()
			close(ch)

			components := []applicationsnapshot.Component{}
			var allErrors error = nil
			for r := range ch {
				if r.err != nil {
					e := fmt.Errorf("error validating image %s of component %s: %w", r.component.ContainerImage, r.component.Name, r.err)
					allErrors = multierror.Append(allErrors, e)
				} else {
					components = append(components, r.component)
				}
			}

			report, err, success := applicationsnapshot.Report(components)
			if allErrors != nil {
				return multierror.Append(allErrors, err)
			}

			if arguments.output != "" {
				if err := ioutil.WriteFile(arguments.output, []byte(report), 0644); err != nil {
					return multierror.Append(allErrors, err)
				}
				fmt.Printf("Report written to %s\n", arguments.output)
			} else {
				_, err := cmd.OutOrStdout().Write([]byte(report))
				if err != nil {
					return multierror.Append(allErrors, err)
				}
			}

			if arguments.strict && !success {
				// TODO: replace this with proper message and exit code 1.
				return errors.New("success criteria not met")
			}

			return nil
		},
	}

	evalCmd.Flags().StringVar(&arguments.policyConfiguration, "policy", "ec-policy", "Policy configuration name")

	evalCmd.Flags().StringVar(&arguments.imageRef, "image", "", "Image reference")
	if arguments.input != "" || arguments.filepath != "" {
		err := evalCmd.MarkFlagRequired("image")
		if err != nil {
			// error can occur if the flag doesn't exist, let's fail and fix this
			panic(err)
		}
	}

	evalCmd.Flags().StringVar(&arguments.publicKey, "public-key", "", "Public key")
	err := evalCmd.MarkFlagRequired("public-key")
	if err != nil {
		// error can occur if the flag doesn't exist, let's fail and fix this
		panic(err)
	}

	evalCmd.Flags().StringVar(&arguments.rekorURL, "rekor-url", "", "Rekor URL")

	evalCmd.Flags().BoolVar(&arguments.strict, "strict", false, "Enable strict mode")

	evalCmd.Flags().StringVar(&arguments.filepath, "filepath", "", "Path to ApplicationSnapshot JSON")
	evalCmd.Flags().StringVar(&arguments.input, "input", "", "ApplicationSnapshot JSON string")
	evalCmd.Flags().StringVar(&arguments.output, "output-file", "", "Path to output file")
	return evalCmd
}

func determineInputSpec(arguments args) (*appstudioshared.ApplicationSnapshotSpec, error) {
	var appSnapshot appstudioshared.ApplicationSnapshotSpec

	// read ApplicationSnapshot provided as a file
	filepath := arguments.filepath
	if filepath != "" {
		utils.Trace("Reading application snapshot from %s", filepath)
		j, err := ioutil.ReadFile(arguments.filepath)
		if err != nil {
			utils.Error("Failed to read application snapshot from %s")
			return nil, err
		}

		utils.Trace("Parsing application snapshot data from %s", filepath)
		err = json.Unmarshal(j, &appSnapshot)
		if err != nil {
			utils.Error("Unable to parse json snapshot data in %s", filepath)
			return nil, err
		}

		utils.Info("Application snapshot loaded from %s", filepath)
		utils.Trace("Application snapshot:\n  %s", appSnapshot)
		return &appSnapshot, nil
	}

	// read ApplicationSnapshot provided as a string
	input := arguments.input
	if input != "" {
		utils.Info("Reading application snapshot from input param")
		// Unmarshall json into struct, exit on failure
		if err := json.Unmarshal([]byte(input), &appSnapshot); err != nil {
			utils.Error("Unable to parse json snapshot data from input param")
			return nil, err
		}

		utils.Info("Application snapshot loaded from input param")
		utils.Trace("Application snapshot:\n  %s", appSnapshot)
		return &appSnapshot, nil
	}

	// create ApplicationSnapshot with a single image
	imageRef := arguments.imageRef
	if imageRef != "" {
		utils.Info("Generating application snapshot from image ref")
		result := &appstudioshared.ApplicationSnapshotSpec{
			Components: []appstudioshared.ApplicationSnapshotComponent{
				{
					Name:           "Unnamed",
					ContainerImage: arguments.imageRef,
				},
			},
		}
		utils.Trace("Application snapshot:\n  %s", *result)
		return result, nil
	}

	utils.Error("Not able to find or create an application snapshot!")
	return nil, errors.New("Unable to load an application snapshot to validate")
}

func validateImage(ctx context.Context, imageRef, policyConfiguration, publicKey, rekorURL string) (*policy.Output, error) {
	imageValidator, err := image.NewImageValidator(ctx, imageRef, publicKey, rekorURL)
	if err != nil {
		return nil, err
	}

	policyEvaluator, err := policy.NewPolicyEvaluator(policyConfiguration)
	if err != nil {
		return nil, err
	}

	return validateImageWith(ctx, imageRef, policyConfiguration, publicKey, rekorURL, imageValidator, policyEvaluator)
}

func validateImageWith(ctx context.Context, imageRef, policyConfiguration, publicKey, rekorURL string, imageValidator image.ImageValidator, policyEvaluator policy.PolicyEvaluator) (*policy.Output, error) {
	out := &policy.Output{}
	if err := imageValidator.ValidateImageSignature(ctx); err != nil {
		out.SetImageSignatureCheck(false, err.Error())
	} else {
		out.SetImageSignatureCheck(true, "success")
	}

	if err := imageValidator.ValidateAttestationSignature(ctx); err != nil {
		out.SetAttestationSignatureCheck(false, err.Error())
	} else {
		out.SetAttestationSignatureCheck(true, "success")
	}

	results, err := policyEvaluator.Evaluate(ctx, imageValidator.Attestations())
	if err != nil {
		return nil, err
	}
	out.SetPolicyCheck(results)

	return out, nil
}
