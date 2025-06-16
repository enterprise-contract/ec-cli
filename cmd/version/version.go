// Copyright The Conforma Contributors
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

package version

import (
	j "encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/conforma/cli/internal/version"
)

var VersionCmd *cobra.Command

func init() {
	var json bool
	var short bool

	VersionCmd = &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			var info *version.VersionInfo
			var err error
			if info, err = version.ComputeInfo(); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			switch {
			case json:
				return j.NewEncoder(out).Encode(info)
			case short:
				_, err := fmt.Fprint(out, info.Version)
				return err
			default:
				_, err := fmt.Fprint(out, info)
				return err
			}
		},
	}

	VersionCmd.Flags().BoolVarP(&json, "json", "j", false, "JSON output")
	VersionCmd.Flags().BoolVarP(&short, "short", "s", false, "Only output the version")
}
