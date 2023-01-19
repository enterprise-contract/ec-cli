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
	"bytes"
	j "encoding/json"
	"errors"
	"fmt"
	dbg "runtime/debug"
	"text/tabwriter"
	"time"

	"github.com/hako/durafmt"
	"github.com/spf13/cobra"
)

// Version of the `ec` CLI, set at build time to git id
var Version = "development"

var readBuildInfo = dbg.ReadBuildInfo

type ComponentInfo struct {
	Name    string
	Version string
}

type VersionInfo struct {
	Version    string
	Commit     string
	ChangedOn  time.Time
	Components []ComponentInfo
}

func (v VersionInfo) String() string {
	var buffy bytes.Buffer
	w := tabwriter.NewWriter(&buffy, 10, 1, 2, ' ', 0)
	fmt.Fprintf(w, "Version\t%s\n", v.Version)
	fmt.Fprintf(w, "Source ID\t%s\n", v.Commit)
	fmt.Fprintf(w, "Change date\t%s (%s ago)\n", v.ChangedOn, durafmt.ParseShort(time.Since(v.ChangedOn)))

	for _, c := range v.Components {
		fmt.Fprintf(w, "%s\t%s\n", c.Name, c.Version)
	}
	w.Flush()

	return buffy.String()
}

func init() {
	var json bool
	var short bool

	var cmd = cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			var info *VersionInfo
			var err error
			if info, err = computeInfo(); err != nil {
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

	cmd.Flags().BoolVarP(&json, "json", "j", false, "JSON output")
	cmd.Flags().BoolVarP(&short, "short", "s", false, "Only output the version")

	RootCmd.AddCommand(&cmd)
}

func computeInfo() (*VersionInfo, error) {
	buildInfo, ok := readBuildInfo()
	if !ok {
		return nil, errors.New("no build info available")
	}

	info := VersionInfo{}
	info.Version = Version

	for _, s := range buildInfo.Settings {
		switch s.Key {
		case "vcs.revision":
			info.Commit = s.Value
		case "vcs.time":
			var err error
			if info.ChangedOn, err = time.Parse(time.RFC3339, s.Value); err != nil {
				return nil, err
			}
		}
	}

	info.Components = append(info.Components, dependencyVersion("ECC", "github.com/hacbs-contract/enterprise-contract-controller/api", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("OPA", "github.com/open-policy-agent/opa", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("Conftest", "github.com/open-policy-agent/conftest", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("Red Hat AppStudio (shared)", "github.com/redhat-appstudio/managed-gitops/appstudio-shared", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("Cosign", "github.com/sigstore/cosign", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("Sigstore", "github.com/sigstore/sigstore", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("Rekor", "github.com/sigstore/rekor", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("Tekton Pipeline", "github.com/tektoncd/pipeline", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("Kubernetes", "k8s.io/api", buildInfo.Deps))

	return &info, nil
}

func dependencyVersion(name string, path string, dependencies []*dbg.Module) ComponentInfo {
	ci := ComponentInfo{
		Name:    name,
		Version: "N/A",
	}
	for _, d := range dependencies {
		if d.Path == path {
			ci.Version = d.Version
			break
		}
	}

	return ci
}
