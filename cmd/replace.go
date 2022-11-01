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

	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/hacbs-contract/ec-cli/internal/replacer"
)

const (
	defaultCatalogName    = "tekton"
	defaultRepositoryBase = "gcr.io/tekton-releases/catalog/upstream/"
	defaultHubAPIURL      = "https://api.hub.tekton.dev"
)

type replaceFn func(context.Context, []string, string, bool, *replacer.CatalogOptions) ([]byte, error)

func replaceCmd(replace replaceFn) *cobra.Command {
	var data = struct {
		source           string
		overwrite        bool
		outputFile       string
		catalogName      string
		catalogRepoBase  string
		catalogHubAPIURL string
	}{
		catalogName:      defaultCatalogName,
		catalogRepoBase:  defaultRepositoryBase,
		catalogHubAPIURL: defaultHubAPIURL,
	}

	cmd := &cobra.Command{
		Use:   "replace",
		Short: "Replace image references in a given source",
		Long: `Replace image references in a given source

Given a source, process its contents to identify Tekton bundle
image references and replace them with an updated version.

For any image reference matching the catalog-repo-base, Tekton
Hub is consulted to determine the latest version of the task,
and its latest image reference. The original image reference is
then replaced with its latest version.

If one or more image parameters are provided, they will also be
used to replace image references matching the same OCI repository.
For example, the image reference "example.com/repo:1.2" would
replace the image reference "example.com/repo:1.1". The provided
image reference can inlude a tag, a digest, or both. If a digest
is not provided, this command will query the repository for this
value.

The following source types are supported:

file: simply a file accessible by the local file system. It
  can be optionally prefixed with the string file://

git repo: a reference to a git repository. By default, the
  branch named main is used. Add the suffix #<branch> to
  specify a different branch. This source type is defined by
  any one of the prefixes https:// http:// git://`,
		Example: `Display a modified version of the source file where
all occurences of bundle references from the main Tekton
catalog are replaced with the corresponding latest version:

  ec replace --source resource.yaml

Process all the yaml files in the main branch of a git repository:

  ec replace --source https://git.example.com/org/repo

Specify an alternative branch:

  ec replace --source https://git.example.com/org/repo#my-branch

In addition to the Tekton catalog, also replace occurences of
the provided images:

  ec replace --source resource.yaml <IMAGE> <IMAGE>`,
		RunE: func(cmd *cobra.Command, images []string) (err error) {
			catalogOptions := &replacer.CatalogOptions{
				CatalogName: data.catalogName,
				RepoBase:    data.catalogRepoBase,
				HubAPIURL:   data.catalogHubAPIURL,
			}

			out, err := replace(cmd.Context(), images, data.source, data.overwrite, catalogOptions)
			if err != nil {
				return err
			}

			if data.outputFile == "" {
				_, err = cmd.OutOrStdout().Write(out)
			} else {
				err = afero.WriteFile(fs(cmd.Context()), data.outputFile, out, 0666)
			}

			return
		},
	}

	cmd.Flags().StringVarP(&data.source, "source", "s", data.source,
		"existing YAML file or a git repository reference (required)")

	cmd.Flags().BoolVar(&data.overwrite, "overwrite", data.overwrite,
		"overwrite source file with changes")

	cmd.Flags().StringVarP(&data.outputFile, "output", "o", data.outputFile,
		"write changes to a file. Use empty string for stdout, default behavior")

	cmd.Flags().StringVar(&data.catalogName, "catalog-name", data.catalogName,
		"name of the catalog in the Tekton Hub")

	cmd.Flags().StringVar(&data.catalogRepoBase, "catalog-repo-base", data.catalogRepoBase,
		"base of the OCI repository where images from the Tekton Hub are found. "+
			"The full image reference is created as <catalog-repo-base><name>:<version>")

	cmd.Flags().StringVar(&data.catalogHubAPIURL, "catalog-hub-api", data.catalogHubAPIURL,
		"URL for the Tekton Hub API")

	if err := cmd.MarkFlagRequired("source"); err != nil {
		panic(err)
	}

	return cmd
}

func init() {
	r := replaceCmd(replacer.Replace)
	RootCmd.AddCommand(r)
}
