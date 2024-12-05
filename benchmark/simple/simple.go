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

// Simple benchmark running the @redhat collection policy at a fixed point in
// time with the state of the container image registry contained within the
// data/registry and git state within data/git. The prepare_data.sh script can
// be used to re-populate the data directory.
package main

import (
	"fmt"
	"os"
	"path"

	"golang.org/x/benchmarks/driver"

	"github.com/enterprise-contract/ec-cli/benchmark/internal/registry"
	"github.com/enterprise-contract/ec-cli/benchmark/internal/suite"
	"github.com/enterprise-contract/ec-cli/benchmark/internal/untar"
)

func main() {
	driver.Main("Simple", benchmark)
}

func benchmark() driver.Result {
	dir, err := untar.UnTar("data.tar.gz")
	defer os.RemoveAll(dir)
	if err != nil {
		panic(err)
	}

	r, c, err := registry.Launch(path.Join(dir, "data/registry/data"))
	defer c.Close()
	if err != nil {
		panic(err)
	}

	return driver.Benchmark(perform(r, dir))
}

func perform(r string, dir string) func(n uint64) {
	snapshot := fmt.Sprintf(`{
  "components": [
    {
      "name": "golden-container",
      "containerImage": "%s/konflux-ci/ec-golden-image@sha256:38a2a2e89671eece1a123f57b543612a67ad529bc66c4ad77216b7ae91ba5769",
      "source": {
        "git": {
          "url": "https://github.com/enterprise-contract/golden-container",
          "revision": "c7897261cd04b76226646bed3ee9d76755343d49"
        }
      }
    }
  ]
}`, r)

	policy := fmt.Sprintf(`{
  "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZP/0htjhVt2y0ohjgtIIgICOtQtA\nnaYJRuLprwIv6FDhZ5yFjYUEtsmoNcW7rx2KM6FOXGsCX3BNc7qhHELT+g==\n-----END PUBLIC KEY-----",
  "sources": [
    {
      "data": [
        "git::file://%[2]s/data/git/rhtap-ec-policy.git//data?ref=a524ee2f2f7774f6f360eb64c4cb24004de52aae",
        "oci::%[1]s/konflux-ci/tekton-catalog/data-acceptable-bundles@sha256:8e6da7823756583cc48499f1c051853cbe30b2d1f127f03b6d2effbd6cd207d0"
      ],
      "policy": [
        "oci::%[1]s/enterprise-contract/ec-release-policy@sha256:c7799644ff34322107919302ae0d2099a811b917a600774545d22fdcd3b49b98"
      ],
      "config": {
        "include": [
          "@redhat"
        ],
      },
    }
  ]
}`, r, dir)

	return func(n uint64) {
		driver.Parallel(n, 1, func() {
			if err := suite.Execute([]string{
				"validate",
				"image",
				"--json-input",
				snapshot,
				"--policy",
				policy,
				"--ignore-rekor",
				"--effective-time",
				"2024-11-28T00:00:00Z",
			}); err != nil {
				panic(err)
			}
		})
	}
}
