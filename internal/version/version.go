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

package version

import (
	"bytes"
	"errors"
	"fmt"
	dbg "runtime/debug"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/hako/durafmt"
)

// Version string for the `ec` CLI
// Set at build time using the output from hack/derive-version.sh
// Example values: v0.6.104, v0.5.167+redhat, v0.6.175-ci-fb5e4c83
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

func ComputeInfo() (*VersionInfo, error) {
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

	info.Components = append(info.Components, dependencyVersion("ECC", "github.com/enterprise-contract/enterprise-contract-controller/api", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("OPA", "github.com/open-policy-agent/opa", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("Conftest", "github.com/open-policy-agent/conftest", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("Cosign", "github.com/sigstore/cosign/v2", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("Sigstore", "github.com/sigstore/sigstore", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("Rekor", "github.com/sigstore/rekor", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("Tekton Pipeline", "github.com/tektoncd/pipeline", buildInfo.Deps))
	info.Components = append(info.Components, dependencyVersion("Kubernetes Client", "k8s.io/api", buildInfo.Deps))

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

// For productized Red Hat builds we currently want to continue using the
// "Enterprise Contract" name. Determine if we're a productized Red Hat build
// by looking at the value of Version. See also the build arg BUILD_SUFFIX,
// and hack/derive-version.sh.

// Use a var so we aren't recalculating every time CliName is called
var (
	cliName      string
	cliShortName string
)

func setCliName() {
	cliName = "Conforma"
	cliShortName = "Conforma"
	if strings.HasSuffix(Version, "+redhat") {
		cliName = "Enterprise Contract"
		cliShortName = "EC"
	}
}

func CliName() string {
	if cliName != "" {
		return cliName
	}
	setCliName()
	return cliName
}

func CliShortName() string {
	if cliShortName != "" {
		return cliShortName
	}
	setCliName()
	return cliShortName
}
