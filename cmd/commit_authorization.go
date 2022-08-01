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
	"log"

	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	"github.com/spf13/cobra"

	"github.com/hacbs-contract/ec-cli/internal/applicationsnapshot"
	"github.com/hacbs-contract/ec-cli/internal/image"
)

func commitAuthorizationCmd() *cobra.Command {
	var data = struct {
		imageRef  string
		publicKey string
		filePath  string
		input     string
		spec      *appstudioshared.ApplicationSnapshotSpec
	}{
		imageRef:  "",
		publicKey: "",
	}
	cmd := &cobra.Command{
		Use:   "commit",
		Short: "Capture signed off signatures from a source (github repo, Jira)",
		Long: `Supported sign off sources are commits captured from a git repo and jira issues.
               The git sources return a signed off value and the git commit. The jira issue is
			   a TODO, but will return the Jira issue with any sign off values.`,

		PreRunE: func(cmd *cobra.Command, args []string) error {
			spec, err := applicationsnapshot.DetermineInputSpec(data.filePath, data.input, data.imageRef)
			if err != nil {
				return err
			}

			data.spec = spec

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, comp := range data.spec.Components {
				err := validateGitSource(cmd.Context(), comp.ContainerImage, data.publicKey)
				if err != nil {
					log.Println(err)
					continue
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&data.publicKey, "public-key", "", "Public key")
	cmd.Flags().StringVar(&data.imageRef, "image-ref", "", "The OCI repo to fetch the attestation from.")
	cmd.Flags().StringVarP(&data.filePath, "file-path", "f", "", "Path to ApplicationSnapshot JSON file")
	cmd.Flags().StringVarP(&data.input, "json-input", "j", "", "ApplicationSnapshot JSON string")

	return cmd
}

func validateGitSource(ctx context.Context, imageRef, publicKey string) error {
	imageValidator, err := image.NewImageValidator(ctx, imageRef, publicKey, "")
	if err != nil {
		return err
	}

	validatedImage, err := imageValidator.ValidateImage(ctx)
	if err != nil {
		return err
	}

	for _, att := range validatedImage.Attestations {
		gitSource, err := att.NewGitSource()
		if err != nil {
			return err
		}

		authorization, err := image.GetAuthorization(gitSource)
		if err != nil {
			return err
		}

		err = image.PrintAuthorization(authorization)
		if err != nil {
			continue
		}
	}
	return nil
}
