// Copyright Red Hat.
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
	"log"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	"github.com/enterprise-contract/ec-cli/internal/image"
)

func k8sResourceAuthorizationCmd() *cobra.Command {
	var data = struct {
		policyConfiguration string
	}{}
	cmd := &cobra.Command{
		Use:   "k8s-resource",
		Short: "Fetch authorizations from a kubernetes resource",

		Long: hd.Doc(`
			Fetch authorizations from a kubernetes resource

			Authorizations are defined within the EnterpriseContractPolicy
			custom resource.

			NOTE: All authorizations are fetched from the kubernetes resource.
		`),

		Example: hd.Doc(`
			Fetch authorizations using named resource:

			  ec fetch k8s-resource --policy <namespace>/<resource>

			Fetch authorizations from a local EnterpriseContractPolicy spec:

			  ec fetch k8s-resource --policy "$(cat /path/to/ecp.json)"
		`),

		RunE: func(cmd *cobra.Command, args []string) error {
			err := printK8sAuthorization(
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

func printK8sAuthorization(ctx context.Context, policyConfiguration string) error {
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
