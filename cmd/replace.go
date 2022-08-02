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
		source           string
		overwrite        bool
		outputFile       string
		catalogName      string
		catalogRepoBase  string
		catalogHubAPIURL string
	}{
		catalogName:      "tekton",
		catalogRepoBase:  "gcr.io/tekton-releases/catalog/upstream/",
		catalogHubAPIURL: "https://api.hub.tekton.dev",
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
				CatalogName: data.catalogName,
				RepoBase:    data.catalogRepoBase,
				HubAPIURL:   data.catalogHubAPIURL,
			}

			out, err := replace(images, data.source, catalogOptions)
			if err != nil {
				return err
			}

			if data.outputFile == "" {
				fmt.Println(string(out))
			} else {
				f, err := os.Create(data.outputFile)
				if err != nil {
					return err
				}
				defer f.Close()
				_, err = f.Write(out)
				if err != nil {
					return err
				}
			}

			if data.overwrite {
				stat, err := os.Stat(data.source)
				if err != nil {
					return err
				}
				f, err := os.OpenFile(data.source, os.O_RDWR, stat.Mode())
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

	cmd.Flags().StringVarP(&data.source, "source", "s", data.source,
		"REQUIRED - An existing YAML file")

	cmd.Flags().BoolVar(&data.overwrite, "overwrite", data.overwrite,
		"Overwrite source file with changes")

	cmd.Flags().StringVarP(&data.outputFile, "output", "o", data.outputFile,
		"Write changes to a file. Use empty string for stdout, default behavior")

	cmd.Flags().StringVar(&data.catalogName, "catalog-name", data.catalogName,
		"Name of the catalog in the Tekton Hub")

	cmd.Flags().StringVar(&data.catalogRepoBase, "catalog-repo-base", data.catalogRepoBase,
		"Base of the OCI repository where images from the Tekton Hub are found. "+
			"The full image reference is created as <base><name>:<version>")

	cmd.Flags().StringVar(&data.catalogHubAPIURL, "catalog-hub-api", data.catalogHubAPIURL,
		"URL for the Tekton Hub API")

	// TODO: We should check the error result here
	_ = cmd.MarkFlagRequired("image")
	_ = cmd.MarkFlagRequired("source")

	return cmd
}

func init() {
	r := replaceCmd(replacer.Replace)
	RootCmd.AddCommand(r)
}
