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

package cli

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/conforma/cli/cmd"
)

//go:embed cli.tmpl
var cliTemplateText string

//go:embed nav.tmpl
var cliNavTemplateText string

var commandTemplate *template.Template

var cliNavTemplate *template.Template

type option struct {
	Name         string
	Shorthand    string
	DefaultValue string
	Usage        string
}

func init() {
	commandTemplate = template.Must(template.New("cli-reference").Funcs(template.FuncMap{
		"options":    options,
		"replaceAll": strings.ReplaceAll,
	}).Parse(cliTemplateText))

	cliNavTemplate = template.Must(template.New("cli-nav").Funcs(template.FuncMap{
		"docname":  docname,
		"commands": commands,
	}).Parse(cliNavTemplateText))
}

func GenerateCommandLineDocumentation(module string) error {
	if err := generateCommandReference(cmd.RootCmd, module); err != nil {
		return err
	}

	if err := generateCommandReferenceNav(cmd.RootCmd, module); err != nil {
		return err
	}

	return nil
}

func generateCommandReference(cmd *cobra.Command, module string) error {
	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}

		if err := generateCommandReference(c, module); err != nil {
			return fmt.Errorf("generating Asciidoc for command %q: %w", c.Name(), err)
		}
	}

	cmd.InitDefaultHelpCmd()
	cmd.InitDefaultHelpFlag()

	docpath := filepath.Join(module, "pages", docname(cmd))
	f, err := os.Create(docpath)
	if err != nil {
		return fmt.Errorf("creating file %q: %w", docpath, err)
	}
	defer f.Close()

	return commandTemplate.Execute(f, cmd)
}

func generateCommandReferenceNav(root *cobra.Command, module string) error {
	navpath := filepath.Join(module, "partials", "cli_nav.adoc")
	f, err := os.Create(navpath)
	if err != nil {
		return fmt.Errorf("creating file %q: %w", navpath, err)
	}
	defer f.Close()

	return cliNavTemplate.Execute(f, root)
}

func commands(cmd *cobra.Command) []*cobra.Command {
	cmds := make([]*cobra.Command, 0, 50)
	cmds = append(cmds, cmd)

	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}

		cmds = append(cmds, commands(c)...)
	}

	return cmds
}

func docname(cmd *cobra.Command) string {
	return fmt.Sprintf("%s.adoc", strings.ReplaceAll(cmd.CommandPath(), " ", "_"))
}

func options(flags *pflag.FlagSet) []option {
	var result []option

	flags.VisitAll(func(flag *pflag.Flag) {
		if !(len(flag.ShorthandDeprecated) > 0) && len(flag.Shorthand) > 0 {
			opt := option{
				flag.Name,
				flag.Shorthand,
				flag.DefValue,
				flag.Usage,
			}
			result = append(result, opt)
		} else {
			opt := option{
				Name:         flag.Name,
				DefaultValue: flag.DefValue,
				Usage:        flag.Usage,
			}
			result = append(result, opt)
		}
	})

	return result
}
