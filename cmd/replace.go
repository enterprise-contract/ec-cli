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
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/hacbs-contract/ec-cli/internal/image"
)

type replaceFn func([]string, string) ([]byte, error)

func replaceCmd(replace replaceFn) *cobra.Command {
	var data = struct {
		Source     string
		Overwrite  bool
		OutputFile string
	}{}

	cmd := &cobra.Command{
		Use:   "replace",
		Short: "Replace image references in the given input",
		Example: `ec replace --source <source path> <image uri> [<image uri> ...]

# replace all occurences of an image reference in source file
ec replace --source resource.yaml <IMAGE>

# replace all occurences of multiple image references in source file
ec replace --source resource.yaml <IMAGE> <IMAGE>`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, images []string) (err error) {

			out, err := replace(images, data.Source)
			if err != nil {
				return err
			}

			if data.OutputFile == "" {
				fmt.Println(string(out))
			} else {
				f, err := os.Create(data.OutputFile)
				if err != nil {
					return err
				}
				defer f.Close()
				_, err = f.Write(out)
				if err != nil {
					return err
				}
			}

			if data.Overwrite {
				stat, err := os.Stat(data.Source)
				if err != nil {
					return err
				}
				f, err := os.OpenFile(data.Source, os.O_RDWR, stat.Mode())
				if err != nil {
					return err
				}
				defer f.Close()
				_, err = f.Write(out)
				if err != nil {
					return err
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&data.Source, "source", "s", data.Source,
		"REQUIRED - An existing YAML file")

	cmd.Flags().BoolVar(&data.Overwrite, "overwrite", data.Overwrite,
		"Overwrite source file with changes")

	cmd.Flags().StringVarP(&data.OutputFile, "output", "o", data.OutputFile,
		"Write changes to a file. Use empty string for stdout, default behavior")

	// TODO: We should check the error result here
	_ = cmd.MarkFlagRequired("image")
	_ = cmd.MarkFlagRequired("source")

	return cmd
}

func init() {
	r := replaceCmd(replace)
	rootCmd.AddCommand(r)
}

type imageReplacer struct {
	*image.ImageReference
	regex *regexp.Regexp
}

func (i *imageReplacer) match(b []byte) bool {
	return i.regex.Match(b)
}

func (i *imageReplacer) replace(b []byte) []byte {
	return i.regex.ReplaceAll(b, []byte(i.String()))
}

func NewimageReplacer(ref image.ImageReference) (*imageReplacer, error) {
	regex, err := regexp.Compile(ref.Repository + `(:|@)\S+`)
	if err != nil {
		return nil, err
	}
	return &imageReplacer{&ref, regex}, nil
}

func replace(images []string, source string) ([]byte, error) {
	resolvedImages, err := image.ParseAndResolveAll(images)
	if err != nil {
		return nil, err
	}

	replacers := make([]*imageReplacer, 0, len(resolvedImages))
	for _, image := range resolvedImages {
		replacer, err := NewimageReplacer(image)
		if err != nil {
			return nil, err
		}
		replacers = append(replacers, replacer)
	}

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
		for _, replacer := range replacers {
			if replacer.match(line) {
				line = replacer.replace(line)
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
