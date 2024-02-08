// Copyright The Enterprise Contract Contributors
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

package track

import (
	"context"
	"errors"
	"os"
	"strings"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/enterprise-contract/ec-cli/internal/utils"
)

type trackBundleFn func(context.Context, []string, []byte, bool, bool) ([]byte, error)
type pullImageFn func(context.Context, string) ([]byte, error)
type pushImageFn func(context.Context, string, []byte, string) error

func trackBundleCmd(track trackBundleFn, pullImage pullImageFn, pushImage pushImageFn) *cobra.Command {
	var params = struct {
		bundles []string
		input   string
		prune   bool
		replace bool
		output  string
		freshen bool
	}{
		prune: true,
	}

	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Record tracking information about Tekton bundles",

		Long: hd.Doc(`
			Record tracking information about Tekton bundles

			Given one or more Tekton Bundles, categorize each as "task-bundles",
			ignoring those that are not. Then, generate a YAML representation of
			this categorization.

			Each Tekton Bundle is expected to be a proper OCI image reference. They
			may contain a tag, a digest, or both. If a digest is not provided, this
			command will query the registry to determine its value. Either a tag
			or a digest is required.

			The output is meant to assist enforcement of policies that ensure the
			most recent Tekton Bundle is used. As such, each entry contains an
			"effective_on" date which is set to 30 days from today. This indicates
			the Tekton Bundle usage should be updated within that period.

			If --prune is set, on by default, non-acceptable entries are removed.
			Any entry with an effective_on date in the future, and the entry with
			the most recent effective_on date *not* in the future are considered
			acceptable.
		`),

		Example: hd.Doc(`
			Track multiple bundles:

			  ec track bundle --bundle <IMAGE1> --bundle <IMAGE2>

			Save tracking information into a new tracking file:

			  ec track bundle --bundle <IMAGE1> --output <path/to/new/file>

			Save tracking information into an image registry:

			  ec track bundle --bundle <IMAGE1> --output <oci:registry.io/repository/image:tag>

			Extend an existing tracking file with a new bundle:

			  ec track bundle --bundle <IMAGE1> --input <path/to/input/file>

			Extend an existing tracking file with a new bundle and save changes:

			  ec track bundle --bundle <IMAGE1> --input <path/to/input/file> --replace

			Extend an existing tracking image with a new bundle and push to an image registry:

			  ec track bundle --bundle <IMAGE1> --input <oci:registry.io/repository/image:tag> --replace

			Skip pruning for unacceptable entries:

			  ec track bundle --bundle <IMAGE1> --input <path/to/input/file> --prune=false

			Update existing acceptable bundles:

			  ec track bundle --input <path/to/input/file> --output <path/to/input/file> --freshen
		`),

		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(params.bundles) == 0 && params.input == "" {
				return errors.New("neither --bundle nor --input was provided")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// capture the command and arguments so we can keep track of what
			// Tekton bundles were used to getnerate the OPA/Conftest bundle
			invocation := strings.Join(os.Args, " ")
			fs := utils.FS(cmd.Context())

			var data []byte
			if strings.HasPrefix(params.input, "oci:") {
				data, err = pullImage(cmd.Context(), strings.TrimPrefix(params.input, "oci:"))
			} else if params.input != "" {
				data, err = afero.ReadFile(fs, params.input)
			}
			if err != nil {
				return err
			}

			out, err := track(cmd.Context(), params.bundles, data, params.prune, params.freshen)
			if err != nil {
				return err
			}

			switch {
			case params.output == "":
				_, err = cmd.OutOrStdout().Write(out)
			case strings.HasPrefix(params.output, "oci:"):
				err = pushImage(cmd.Context(), strings.TrimPrefix(params.output, "oci:"), out, invocation)
			default:
				err = afero.WriteFile(fs, params.output, out, 0666)
			}

			if err != nil {
				return
			}

			if params.replace && params.input != "" {
				if strings.HasPrefix(params.input, "oci:") {
					err = pushImage(cmd.Context(), strings.TrimPrefix(params.input, "oci:"), out, invocation)
				} else {
					var perm os.FileMode
					if stat, err := fs.Stat(params.input); err != nil {
						return err
					} else {
						perm = stat.Mode()
					}

					err = afero.WriteFile(fs, params.input, out, perm)
				}
			}

			return
		},
	}

	cmd.Flags().StringVarP(&params.input, "input", "i", params.input, "existing tracking file")

	cmd.Flags().StringSliceVarP(&params.bundles, "bundle", "b", params.bundles,
		"bundle image reference to track - may be used multiple times (required)")

	cmd.Flags().BoolVarP(&params.prune, "prune", "p", params.prune,
		"remove entries that are no longer acceptable, i.e. a newer entry already effective exists")

	cmd.Flags().BoolVarP(&params.replace, "replace", "r", params.replace, "write changes to input file")

	cmd.Flags().StringVarP(&params.output, "output", "o", params.output,
		"write modified tracking file to a file. Use empty string for stdout, default behavior")

	cmd.Flags().BoolVar(&params.freshen, "freshen", params.freshen, "resolve image tags to catch updates and use the latest image for the tag")

	return cmd
}
