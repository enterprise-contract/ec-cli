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
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
	"github.com/tektoncd/pipeline/pkg/remote/oci"

	"github.com/hacbs-contract/ec-cli/internal/image"
	"github.com/hacbs-contract/ec-cli/internal/tracker"
)

type trackBundleFn func(context.Context, []string, string, tracker.Collector) ([]byte, error)

func trackBundleCmd(track trackBundleFn) *cobra.Command {
	var data = struct {
		Bundles    []string
		Input      string
		Replace    bool
		OutputFile string
	}{}

	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Record tracking information about Tekton bundles",
		Long: `Record tracking information about Tekton bundles

Given one or more Tekton Bundles, categorize each as "pipeline-bundles",
"tekton-bundles", or both. Then, generate a YAML represenation of this
categorization.

Each Tekton Bundle is expected to be a proper OCI image reference. They
may contain a tag, a digest, or both. If a digest is not provided, this
command will query the registry to determine its value. Either a tag
or a digest is required.

The output is meant to assist enforcement of policies that ensure the
most recent Tekton Bundle is used. As such, each entry contains an
"effective_on" date which is set to 30 days from today. This indicates
the Tekton Bundle usage should be updated within that period.`,
		Example: `Track multiple bundles:

  ec track bundle --bundle <IMAGE1> --bundle <IMAGE2>

Save tracking information into a new tracking file:

  ec track bundle --bundle <IMAGE1> --output <path/to/new/file>

Extend an existing tracking file with a new bundle:

  ec track bundle --bundle <IMAGE1> --input <path/to/input/file>

Extend an existing tracking file with a new bundle and save changes:

  ec track bundle --bundle <IMAGE1> --input <path/to/input/file> --replace`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {

			out, err := track(cmd.Context(), data.Bundles, data.Input, tektonBundleCollector)
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

			if data.Input != "" && data.Replace {
				stat, err := os.Stat(data.Input)
				if err != nil {
					return err
				}
				f, err := os.OpenFile(data.Input, os.O_RDWR, stat.Mode())
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

	cmd.Flags().StringVarP(&data.Input, "input", "i", data.Input, "existing tracking file")

	cmd.Flags().StringSliceVarP(&data.Bundles, "bundle", "b", data.Bundles,
		"bundle image reference to track - may be used multiple times (required)")

	cmd.Flags().BoolVarP(&data.Replace, "replace", "r", data.Replace, "write changes to input file")

	cmd.Flags().StringVarP(&data.OutputFile, "output", "o", data.OutputFile,
		"write modified tracking file to a file. Use empty string for stdout, default behavior")

	if err := cmd.MarkFlagRequired("bundle"); err != nil {
		panic(err)
	}

	return cmd
}

var fetchImage = remote.Image

func tektonBundleCollector(ctx context.Context, ref image.ImageReference) ([]string, error) {
	img, err := fetchImage(ref.Ref(), remote.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	manifest, err := img.Manifest()
	if err != nil {
		return nil, err
	}

	collectionsMap := map[string]bool{}
	for _, layer := range manifest.Layers {
		if kind, ok := layer.Annotations[oci.KindAnnotation]; ok {
			collectionsMap[kind] = true
		}
	}

	collections := make([]string, 0, len(collectionsMap))
	for c := range collectionsMap {
		collections = append(collections, c)
	}

	return collections, nil
}
