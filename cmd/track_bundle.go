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
	"os"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

type trackBundleFn func(context.Context, afero.Fs, []string, string) ([]byte, error)

func trackBundleCmd(track trackBundleFn) *cobra.Command {
	var data = struct {
		bundles    []string
		input      string
		replace    bool
		outputFile string
	}{}

	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Record tracking information about Tekton bundles",

		Long: hd.Doc(`
			Record tracking information about Tekton bundles

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
			the Tekton Bundle usage should be updated within that period.

			Additionally, the common set of Tasks referenced by all "important"
			Pipeline definitions are deemed required and displayed as such. An
			"important" Pipeline definition is defined as one that does NOT include
			the label "skip-hacbs-test" set to the value "true".
		`),

		Example: hd.Doc(`
			Track multiple bundles:

			  ec track bundle --bundle <IMAGE1> --bundle <IMAGE2>

			Save tracking information into a new tracking file:

			  ec track bundle --bundle <IMAGE1> --output <path/to/new/file>

			Extend an existing tracking file with a new bundle:

			  ec track bundle --bundle <IMAGE1> --input <path/to/input/file>

			Extend an existing tracking file with a new bundle and save changes:

			  ec track bundle --bundle <IMAGE1> --input <path/to/input/file> --replace
		`),

		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			fs := fs(cmd.Context())

			out, err := track(cmd.Context(), fs, data.bundles, data.input)
			if err != nil {
				return err
			}

			if data.outputFile == "" {
				_, err = cmd.OutOrStdout().Write(out)
			} else {
				err = afero.WriteFile(fs, data.outputFile, out, 0666)
			}

			if err != nil {
				return
			}

			if data.input != "" && data.replace {
				var perm os.FileMode
				if stat, err := fs.Stat(data.input); err != nil {
					return err
				} else {
					perm = stat.Mode()
				}

				err = afero.WriteFile(fs, data.input, out, perm)
			}

			return
		},
	}

	cmd.Flags().StringVarP(&data.input, "input", "i", data.input, "existing tracking file")

	cmd.Flags().StringSliceVarP(&data.bundles, "bundle", "b", data.bundles,
		"bundle image reference to track - may be used multiple times (required)")

	cmd.Flags().BoolVarP(&data.replace, "replace", "r", data.replace, "write changes to input file")

	cmd.Flags().StringVarP(&data.outputFile, "output", "o", data.outputFile,
		"write modified tracking file to a file. Use empty string for stdout, default behavior")

	if err := cmd.MarkFlagRequired("bundle"); err != nil {
		panic(err)
	}

	return cmd
}
