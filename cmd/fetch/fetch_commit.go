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

package fetch

import (
	"context"
	"errors"
	"fmt"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/hashicorp/go-multierror"
	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/hacbs-contract/ec-cli/internal/applicationsnapshot"
	"github.com/hacbs-contract/ec-cli/internal/image"
	"github.com/hacbs-contract/ec-cli/internal/utils"
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
		Short: "Fetch authorizations from a git repository",

		Long: hd.Doc(`
			Fetch authorizations from a git repository

			An authorization, within the context of this command, is loosely
			defined as the person who appears in the "Signed-off-by:" line
			in the git commit message.

			This command also verifies the provided images have been attested
			with the provided public key.

			The git commit and git repository are extracted from the field
			".predicate.materials" of the image attestation.
		`),

		Example: hd.Doc(`
			Process git commit from a single image:

			  ec fetch commit --image-ref <image url> --public-key <path/to/public/key>

			Process git commit from an ApplicationSnapshot Spec file:

			  ec fetch commit --file-path <path/to/ApplicationSnapshot/file> --public-key <path/to/public/key>

			Process git commit from an inline ApplicationSnapshot Spec:

			  ec fetch commit --json-input '{"components":[{"containerImage":"<image url>"}]}' --public-key <path/to/public/key>

			Use public key from a kubernetes secret:

			  ec fetch commit --image-ref <image url> --public-key k8s://<namespace>/<secret-name>
		`),

		PreRunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			spec, err := applicationsnapshot.DetermineInputSpec(utils.FS(ctx), data.filePath, data.input, data.imageRef)
			if err != nil {
				return err
			}

			data.spec = spec

			return nil
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			var errs error
			for _, comp := range data.spec.Components {
				err := validateGitSource(cmd.Context(), comp.ContainerImage, data.publicKey)
				if err != nil {
					errs = multierror.Append(errs, fmt.Errorf("component: %+v - %w", comp, err))
					continue
				}
			}
			return errs
		},
	}

	cmd.Flags().StringVar(&data.publicKey, "public-key", data.publicKey, "path to the public key associated with the image attestation(s)")
	cmd.Flags().StringVar(&data.imageRef, "image-ref", data.imageRef, "OCI reference to the attested image")
	cmd.Flags().StringVarP(&data.filePath, "file-path", "f", data.filePath, "path to ApplicationSnapshot Spec JSON file")
	cmd.Flags().StringVarP(&data.input, "json-input", "j", data.input, "JSON representation of an ApplicationSnapshot Spec")

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

	var gitSourceFound bool
	for _, att := range validatedImage.Attestations {
		gitSource, err := att.NewGitSource()
		if err != nil {
			log.Debug("attestation has empty 'predicate.material' entry")
			continue
		}
		gitSourceFound = true

		authorization, err := image.GetAuthorization(ctx, gitSource)
		if err != nil {
			return err
		}

		err = image.PrintAuthorization(authorization)
		if err != nil {
			continue
		}
	}
	if !gitSourceFound {
		return errors.New("all attestations for component failed to provide valid '.Predicate.Material' entry")
	}
	return nil
}
