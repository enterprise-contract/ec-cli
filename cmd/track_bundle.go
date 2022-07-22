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
		Short: "Record tracking information about the bundle",
		Args:  cobra.NoArgs,
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

	cmd.Flags().StringVarP(&data.Input, "input", "i", data.Input, "An existing tracking file")

	cmd.Flags().StringSliceVarP(&data.Bundles, "bundle", "b", data.Bundles,
		"REQUIRED - The bundle image reference to  track - may be used multiple times")

	cmd.Flags().BoolVarP(&data.Replace, "replace", "r", data.Replace, "Modify input file in-place.")

	cmd.Flags().StringVarP(&data.OutputFile, "output", "o", data.OutputFile,
		"Write modified tracking file to a file. Use empty string for stdout, default behavior")

	// TODO: We should check the error result here
	_ = cmd.MarkFlagRequired("bundle")

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
