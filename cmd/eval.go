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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/hacbs-contract/ec-cli/internal/applicationsnapshot"
	"github.com/hacbs-contract/ec-cli/internal/image"
	"github.com/hacbs-contract/ec-cli/internal/policy"
	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(evalCmd())
}

func evalCmd() *cobra.Command {
	var arguments = struct {
		policyConfiguration string
		imageRef            string
		publicKey           string
		rekorURL            string
		strict              bool
		input               string
		filepath            string
		output              string
	}{
		rekorURL: "https://rekor.sigstore.dev/",
	}
	var snapshotSpec *appstudioshared.ApplicationSnapshotSpec

	evalCmd := &cobra.Command{
		Use:   "eval",
		Short: "Evaluate enterprise contract",
		Long:  `TODO: description`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if arguments.input != "" || arguments.filepath != "" {
				var jsonstr string
				// Filepath handler, reads the file and stores the content as string
				if arguments.filepath != "" {
					file, err := ioutil.ReadFile(arguments.filepath)

					if err != nil {
						return err
					}

					jsonstr = string(file)
				}

				// Input handler
				if arguments.input != "" {
					jsonstr = arguments.input
				}
				// Unmarshall json into struct, exit on failure
				if err := json.Unmarshal([]byte(jsonstr), &snapshotSpec); err != nil {
					return err
				}

				if snapshotSpec == nil {
					return errors.New("ApplicationSnapshot input could not be unmarshalled.")
				}
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			//TODO: refactor once we handle application snapshots
			if arguments.input != "" || arguments.filepath != "" {
				report, err := applicationsnapshot.Report(snapshotSpec)
				if err != nil {
					return err
				}

				if arguments.output != "" {
					if err := ioutil.WriteFile(arguments.output, []byte(report), 0644); err != nil {
						return err
					}
					fmt.Printf("Report written to %s\n", arguments.output)
				} else {
					fmt.Println(report)
				}
				return nil
			}

			out := &policy.Output{}

			i, err := image.NewImageValidator(cmd.Context(), arguments.imageRef, arguments.publicKey, arguments.rekorURL)
			if err != nil {
				return err
			}

			if err := i.ValidateImageSignature(cmd.Context()); err != nil {
				out.SetImageSignatureCheck(false, err.Error())
				return err
			}
			out.SetImageSignatureCheck(true, "success")

			if err := i.ValidateAttestationSignature(cmd.Context()); err != nil {
				out.SetAttestationSignatureCheck(false, err.Error())
				return err
			}
			out.SetAttestationSignatureCheck(true, "success")

			p, err := policy.NewPolicyEvaluator(arguments.policyConfiguration)
			if err != nil {
				return err
			}

			results, err := p.Evaluate(cmd.Context(), i.Attestations())
			if err != nil {
				return err
			}
			out.SetPolicyCheck(results)

			if out.Print(); err != nil {
				return err
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
