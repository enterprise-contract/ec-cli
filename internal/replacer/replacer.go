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

package replacer

import (
	"bufio"
	"bytes"
	"os"

	"github.com/hacbs-contract/ec-cli/internal/image"
)

func Replace(images []string, source string, opts *CatalogOptions) ([]byte, error) {
	resolvedImages, err := image.ParseAndResolveAll(images)
	if err != nil {
		return nil, err
	}

	replacers := make([]imageReplacer, 0, len(resolvedImages)+1)
	for _, image := range resolvedImages {
		r, err := newBasicImageReplacer(image)
		if err != nil {
			return nil, err
		}
		replacers = append(replacers, r)
	}
	catalogReplacer, err := newCatalogImageReplacer(opts)
	if err != nil {
		return nil, err
	}
	replacers = append(replacers, catalogReplacer)

	sourceFile, err := os.Open(source)
	if err != nil {
		return nil, err
	}
	defer sourceFile.Close()

	scanner := bufio.NewScanner(sourceFile)
	scanner.Split(bufio.ScanLines)

	writer := bytes.NewBuffer(nil)
	for scanner.Scan() {
		line := scanner.Bytes()
		for _, replace := range replacers {
			if replace.match(line) {
				line = replace.replace(line)
			}
		}
		if _, err := writer.Write(line); err != nil {
			return nil, err
		}
		if _, err = writer.WriteString("\n"); err != nil {
			return nil, err
		}
	}
	return writer.Bytes(), nil
}

type CatalogOptions struct {
	CatalogName string
	RepoBase    string
	HubAPIURL   string
}
