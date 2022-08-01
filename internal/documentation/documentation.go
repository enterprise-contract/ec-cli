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
	"fmt"
	"os"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra/doc"

	cmd "github.com/hacbs-contract/ec-cli/cmd"
)

func main() {
	var errs error
	docsdir, ok := os.LookupEnv("EC_CLI_DOCS_DIR")
	if !ok {
		dir, err := os.Getwd()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		docsdir = dir + "/docs"
	}
	mdPath := docsdir + "/md"
	manPath := docsdir + "/man"
	rstPath := docsdir + "/rst"
	paths := []string{mdPath, manPath, rstPath}
	// Disable generated tags
	cmd.RootCmd.DisableAutoGenTag = true

	// Create the target paths
	for _, p := range paths {
		if err := os.MkdirAll(p, os.ModePerm); err != nil {
			errs = multierror.Append(errs, err)
			continue
		}
	}

	// Markdown
	if err := doc.GenMarkdownTree(cmd.RootCmd, mdPath); err != nil {
		errs = multierror.Append(errs, err)
	}

	// Man pages
	if err := doc.GenManTree(cmd.RootCmd, nil, manPath); err != nil {
		errs = multierror.Append(errs, err)
	}

	// ReStructuredText
	if err := doc.GenReSTTree(cmd.RootCmd, rstPath); err != nil {
		errs = multierror.Append(errs, err)
	}

	if errs != nil {
		fmt.Println(errs)
		os.Exit(1)
	}
	os.Exit(0)
}
