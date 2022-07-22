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
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/hacbs-contract/ec-cli/internal/replacer"
)

type replaceFn func([]string, string, *replacer.CatalogOptions) ([]byte, error)

func replaceCmd(replace replaceFn) *cobra.Command {
	var data = struct {
		Source           string
		Overwrite        bool
		OutputFile       string
		CatalogName      string
		CatalogRepoBase  string
		CatalogHubAPIURL string
	}{
		CatalogName:      "tekton",
		CatalogRepoBase:  "gcr.io/tekton-releases/catalog/upstream/",
		CatalogHubAPIURL: "https://api.hub.tekton.dev",
	}

	cmd := &cobra.Command{
		Use:   "replace",
		Short: "Replace image references in the given input",
		Example: `ec replace --source <source path> [<image uri> ...]

Display a modified version of the source file where
all occurences of bundle references from the main Tekton
catalog are replace with the corresponding latest version:

  ec replace --source resource.yaml

In addition to the Tekton catalog, also replace occurences of
the provided image:

  ec replace --source resource.yaml <IMAGE>

In addition to the Tekton catalog, also replace occurences of
the provided images:

  ec replace --source resource.yaml <IMAGE> <IMAGE>`,
		RunE: func(cmd *cobra.Command, images []string) (err error) {
			catalogOptions := &replacer.CatalogOptions{
				CatalogName: data.CatalogName,
				RepoBase:    data.CatalogRepoBase,
				HubAPIURL:   data.CatalogHubAPIURL,
			}

			out, err := replace(images, data.Source, catalogOptions)
			if err != nil {
				return err
			}

			if data.OutputFile == "" {
				fmt.Println(string(out))
			} else {
				f, err := os.Create(data.OutputFile)
				if err != nil {
					return err
				}
				defer f.Close()
				_, err = f.Write(out)
				if err != nil {
					return err
				}
			}

			if data.Overwrite {
				stat, err := os.Stat(data.Source)
				if err != nil {
					return err
				}
				f, err := os.OpenFile(data.Source, os.O_RDWR, stat.Mode())
				if err != nil {
					return err
				}
				defer f.Close()
				_, err = f.Write(out)
				if err != nil {
					return err
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&data.Source, "source", "s", data.Source,
		"REQUIRED - An existing YAML file")

	cmd.Flags().BoolVar(&data.Overwrite, "overwrite", data.Overwrite,
		"Overwrite source file with changes")

	cmd.Flags().StringVarP(&data.OutputFile, "output", "o", data.OutputFile,
		"Write changes to a file. Use empty string for stdout, default behavior")

	cmd.Flags().StringVar(&data.CatalogName, "catalog-name", data.CatalogName,
		"Name of the catalog in the Tekton Hub")

	cmd.Flags().StringVar(&data.CatalogRepoBase, "catalog-repo-base", data.CatalogRepoBase,
		"Base of the OCI repository where images from the Tekton Hub are found. "+
			"The full image reference is created as <base><name>:<version>")

	cmd.Flags().StringVar(&data.CatalogHubAPIURL, "catalog-hub-api", data.CatalogHubAPIURL,
		"URL for the Tekton Hub API")

	// TODO: We should check the error result here
	_ = cmd.MarkFlagRequired("image")
	_ = cmd.MarkFlagRequired("source")

	return cmd
}

func init() {
	r := replaceCmd(replacer.Replace)
	rootCmd.AddCommand(r)
}
