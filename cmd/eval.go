/*
Copyright © 2022 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"github.com/hacbs-contract/ec-cli/cmd/internal/image"
	"github.com/hacbs-contract/ec-cli/cmd/internal/policy"
	"github.com/spf13/cobra"
)

var arguments = struct {
	policyConfiguration string
	imageRef            string
	publicKey           string
	rekorURL            string
	strict              bool
}{
	rekorURL: "https://rekor.sigstore.dev/",
}

func init() {
	rootCmd.AddCommand(evalCmd)

	evalCmd.Flags().StringVar(&arguments.policyConfiguration, "policy", "ec-policy", "Policy configuration name")

	evalCmd.Flags().StringVar(&arguments.imageRef, "image", "", "Image reference")
	evalCmd.MarkFlagRequired("image")

	evalCmd.Flags().StringVar(&arguments.publicKey, "public-key", "", "Public key")
	evalCmd.MarkFlagRequired("public-key")

	evalCmd.Flags().StringVar(&arguments.rekorURL, "rekor-url", "", "Rekor URL")

	evalCmd.Flags().BoolVar(&arguments.strict, "strict", false, "Enable strict mode")
}

var evalCmd = &cobra.Command{
	Use:   "eval",
	Short: "Evaluate enterprise contract",
	Long:  `TODO: description`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		i, err := image.NewImageValidator(cmd.Context(), arguments.imageRef, arguments.publicKey, arguments.rekorURL)
		if err != nil {
			return err
		}

		if err := i.ValidateImageSignature(cmd.Context()); err != nil {
			return err
		}

		if err := i.ValidateAttestationSignature(cmd.Context()); err != nil {
			return err
		}

		p, err := policy.NewPolicyEvaluator(arguments.policyConfiguration)
		if err != nil {
			return err
		}

		results, err := p.Evaluate(cmd.Context(), i.Attestations())
		if err != nil {
			return err
		}

		if err := p.Output(results); err != nil {
			return err
		}

		return nil
	},
}
