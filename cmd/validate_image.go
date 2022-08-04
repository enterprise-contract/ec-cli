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
	"errors"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/hashicorp/go-multierror"
	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	"github.com/spf13/cobra"

	"github.com/hacbs-contract/ec-cli/internal/applicationsnapshot"
	"github.com/hacbs-contract/ec-cli/internal/output"
)

type imageValidationFunc func(ctx context.Context, imageRef, policyConfiguration, publicKey, rekorURL string) (*output.Output, error)

func validateImageCmd(validate imageValidationFunc) *cobra.Command {
	var data = struct {
		policyConfiguration string
		imageRef            string
		publicKey           string
		rekorURL            string
		strict              bool
		input               string
		filePath            string
		output              string
		spec                *appstudioshared.ApplicationSnapshotSpec
	}{
		policyConfiguration: "ec-policy",
		rekorURL:            "https://rekor.sigstore.dev/",
		strict:              false,
	}
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Validates container image conformance with the Enterprise Contract",
		Long: `Validates image signature, signature of related artifacts such as build
attestation signature, transparency logs for the image signature and releated
artifacts, gathers build related data and evaluates the enterprise policy
against it.`,
		Example: `Validate single image "registry/name:tag" with the default policy defined in
the EnterpriseContractPolicy custom resource named "ec-policy" in the current
Kubernetes namespace:

  ec validate image --image registry/name:tag

Validate an application snapshot provided by the ApplicationSnapshot custom
resource provided via a file using a custom public key and a private Rekor
instance in strict mode:

  ec validate image --file-path my-app.yaml --public-key my-key.pem --rekor-url https://rekor.example.org --strict`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			s, err := applicationsnapshot.DetermineInputSpec(data.filePath, data.input, data.imageRef)
			if err != nil {
				return err
			}

			data.spec = s

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			type result struct {
				err       error
				component applicationsnapshot.Component
			}

			appComponents := data.spec.Components

			ch := make(chan result, len(appComponents))

			var lock sync.WaitGroup
			for _, c := range appComponents {
				lock.Add(1)
				go func(comp appstudioshared.ApplicationSnapshotComponent) {
					defer lock.Done()

					out, err := validate(cmd.Context(), comp.ContainerImage, data.policyConfiguration, data.publicKey, data.rekorURL)
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

			var components []applicationsnapshot.Component
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

			if len(data.output) > 0 {
				if err := ioutil.WriteFile(data.output, []byte(report), 0644); err != nil {
					return multierror.Append(allErrors, err)
				}
				fmt.Printf("Report written to %s\n", data.output)
			} else {
				_, err := cmd.OutOrStdout().Write([]byte(report))
				if err != nil {
					return multierror.Append(allErrors, err)
				}
			}

			if data.strict && !success {
				// TODO: replace this with proper message and exit code 1.
				return errors.New("success criteria not met")
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&data.policyConfiguration, "policy", "p", data.policyConfiguration, "Policy configuration name")
	cmd.Flags().StringVarP(&data.imageRef, "image", "i", data.imageRef, "Image reference")
	cmd.Flags().StringVarP(&data.publicKey, "public-key", "k", data.publicKey, "Public key")
	cmd.Flags().StringVarP(&data.rekorURL, "rekor-url", "r", data.rekorURL, "Rekor URL")
	cmd.Flags().StringVarP(&data.filePath, "file-path", "f", data.filePath, "Path to ApplicationSnapshot JSON file")
	cmd.Flags().StringVarP(&data.input, "json-input", "j", data.input, "ApplicationSnapshot JSON string")
	cmd.Flags().StringVarP(&data.output, "output-file", "o", data.output, "Path to output file")
	cmd.Flags().BoolVarP(&data.strict, "strict", "s", data.strict, "Enable strict mode")

	_ = cmd.MarkFlagRequired("public-key")
	if len(data.input) > 0 || len(data.filePath) > 0 {
		_ = cmd.MarkFlagRequired("image")
	}
	return cmd
}
