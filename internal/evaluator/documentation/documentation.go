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

package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"sigs.k8s.io/yaml"

	_ "github.com/enterprise-contract/ec-cli/internal/evaluator" // imports EC OPA builtins
)

const directoryPermissions = 0755
const filePermissions = 0644

var yamlDir = flag.String("yaml", "", "Location of the generated YAML files")

func main() {
	flag.Parse()

	if err := writeBultinsToYAML(*yamlDir); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func writeBultinsToYAML(dir string) error {
	if (dir) == "" {
		dir = "rego-docs"
	}

	if err := os.MkdirAll(dir, directoryPermissions); err != nil {
		return err
	}

	for _, builtin := range ast.Builtins {
		// We only care about the builtins provided by EC.
		if !strings.HasPrefix(builtin.Name, "ec.") {
			continue
		}
		data, err := yaml.Marshal(builtin)
		if err != nil {
			return err
		}

		filename := path.Join(dir, fmt.Sprintf("%s.yaml", builtin.Name))
		if err := os.WriteFile(filename, data, filePermissions); err != nil {
			return err
		}
	}
	return nil
}
