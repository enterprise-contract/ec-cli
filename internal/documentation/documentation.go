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

package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra/doc"

	cmd "github.com/enterprise-contract/ec-cli/cmd"
)

const DirectoryPermissions = 0755

var markdown = flag.String("markdown", "", "Location of the generated MarkDown files")
var man = flag.String("man", "", "Location of the generated Man files")
var rst = flag.String("rst", "", "Location of the generated reStructuredText files")
var yaml = flag.String("yaml", "", "Location of the generated YAML files")

func main() {
	flag.Parse()

	// Disable generated tags
	cmd.RootCmd.DisableAutoGenTag = true

	var err error
	defer func() {
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}()

	// Markdown
	if *markdown != "" {
		if err = os.MkdirAll(*markdown, DirectoryPermissions); err != nil {
			return
		}

		prepender := func(s string) string {
			title := strings.ReplaceAll(strings.TrimSuffix(path.Base(s), ".md"), "_", " ")
			return fmt.Sprintf("---\ntitle: %s\n---\n", title)
		}

		linkHandler := func(s string) string {
			return fmt.Sprintf(`{{< relref "%s" >}}`, strings.TrimSuffix(s, ".md"))
		}

		if err = doc.GenMarkdownTreeCustom(cmd.RootCmd, *markdown, prepender, linkHandler); err != nil {
			return
		}
	}

	// Man pages
	if *man != "" {
		if err = os.MkdirAll(*man, DirectoryPermissions); err != nil {
			return
		}
		if err = doc.GenManTree(cmd.RootCmd, nil, *man); err != nil {
			return
		}
	}

	// ReStructuredText
	if *rst != "" {
		if err = os.MkdirAll(*rst, DirectoryPermissions); err != nil {
			return
		}
		if err = doc.GenReSTTree(cmd.RootCmd, *rst); err != nil {
			return
		}
	}

	// YAML
	if *yaml != "" {
		if err = os.MkdirAll(*yaml, DirectoryPermissions); err != nil {
			return
		}
		if err = doc.GenYamlTree(cmd.RootCmd, *yaml); err != nil {
			return
		}
	}
}
