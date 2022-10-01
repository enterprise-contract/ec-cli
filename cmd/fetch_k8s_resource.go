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

	"github.com/hacbs-contract/ec-cli/internal/image"
	ecc "github.com/hacbs-contract/enterprise-contract-controller/api/v1alpha1"
)

func k8sResourceAuthorizationCmd() *cobra.Command {
	var data = struct {
		policyConfiguration string
		spec                *appstudioshared.ApplicationSnapshotSpec
	}{}
	cmd := &cobra.Command{
		Use:   "k8s-resource",
		Short: "Fetch authorizations from a kubernetes resource",
		Long: `Fetch authorizations from a kubernetes resource

Authorizations are defined within the EnterpriseContractPolicy
custom resource.

This command also verifies the provided images have been attested
with the provided public key.

NOTE: All authorizations are fetched from the kubernetes resource.
It is expected that the caller matches these authorizations with
the corresponding images.`,
		Example: `Validate attestation of a single image and fetch authorizations:

  ec fetch k8s-resource --image-ref <image url> \
      --public-key <path/to/public/key> --namespace <namespace> --resource <resource>

Validate attestation of multiple images from an ApplicationSnapshot Spec
file and fetch authorizations:

  ec fetch k8s-resource --file-path <path/to/ApplicationSnapshot/file> \
      --public-key <path/to/public/key> --namespace <namespace> --resource <resource>

Validate attestation of multiple images from an inline ApplicationSnapshot
Spec and fetch authorizations:

  ec fetch k8s-resource --json-input '{"components":[{"containerImage":"<image url>"}]}' \
      --public-key <path/to/public/key> --namespace <namespace> --resource <resource>

Use public key from a kubernetes secret:

  ec fetch k8s-resource --image-ref <image url> \
     --public-key k8s://<namespace>/<secret-name> --namespace <namespace> --resource <resource>`,

		RunE: func(cmd *cobra.Command, args []string) error {
			err := validateK8sSource(
				cmd.Context(),
				data.policyConfiguration,
			)
			if err != nil {
				log.Println(err)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&data.policyConfiguration, "policy", "p", data.policyConfiguration,
		"EntepriseContractPolicy reference [<namespace>/]<name>")

	return cmd
}

func GetK8sAuthorization(ecp *ecc.EnterpriseContractPolicySpec) error {
	resource, err := image.GetK8sResource(ecp)
	if err != nil {
		return err
	}

	auth, err := resource.GetSignOff()

	err = image.PrintAuthorization(auth)
	if err != nil {
		return err
	}

	return nil
}

func validateK8sSource(ctx context.Context, policyConfiguration string) error {
	k8sSource, err := image.NewK8sSource(policyConfiguration)
	if err != nil {
		return err
	}

	authorization, err := image.GetAuthorization(ctx, k8sSource)
	if err != nil {
		return err
	}

	err = image.PrintAuthorization(authorization)
	if err != nil {
		return err
	}

	return nil
}
