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
	"bytes"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// The package where ec-cli Error interface is declared
const errorPackage = "github.com/hacbs-contract/ec-cli/pkg/error"

// Pattern for the error code: XXNNN
var errorCode = regexp.MustCompile(`[A-Z]{2}\d{3}`)

// When the "error_current" linter makes a pass the collected information needed
// to create fixes in the "error_return" linter is gathered here
type currentInfo struct {
	importNode *ast.GenDecl // if we found the error import node with the error package this gets populated
	varNode    *ast.GenDecl // if we found a variable declaration node this gets populated
	packagePos token.Pos    // the position of the "package" statement
	name       string       // if the error import is found this is the name it was given
	errors     []string     // the existing error codes found
}

func (c *currentInfo) appendErrors(errors ...string) {
	c.errors = append(c.errors, errors...)
}

// importStart returns the start position of the "import" statement or a
// position right after the "package" statement if no imports were found
func (c currentInfo) importStart() token.Pos {
	if c.importNode == nil {
		return c.packagePos + 1
	}

	return c.importNode.Pos()
}

// importEnd returns the end position of the "import" statement or the position
// right after the "package" statement if no imports were found. In some cases
// the end of the import statement is the position of the right parenthesis, and
// if import grouping is not used the end of the line.
func (c currentInfo) importEnd() token.Pos {
	if c.importNode == nil {
		return c.packagePos + 1
	}

	return c.importNode.End()
}

// varStart returns the start position of the variable block, which is either
// the position of the existing var block, or the position at the end of the
// "import" statement if there is no var block.
func (c currentInfo) varStart() token.Pos {
	if c.varNode == nil {
		return c.importEnd()
	}

	return c.varNode.Pos()
}

// varEnd returns the position of the end of the var block, that being either
// end of the line or the position of the right parenthesis if grouping is used;
// or if there is no var statements at all - the end of the "import" statement
func (c currentInfo) varEnd() token.Pos {
	if c.varNode == nil {
		return c.importEnd()
	}

	return c.varNode.End()
}

// currentInfos holds current information for each golang file
type currentInfos struct {
	info map[string]*currentInfo
}

// entry creates or gets the current info for a file path
func (c *currentInfos) entry(path string) *currentInfo {
	if c.info == nil {
		c.info = map[string]*currentInfo{}
	}

	var i *currentInfo
	var ok bool
	if i, ok = c.info[path]; !ok {
		i = &currentInfo{}
		c.info[path] = i
	}

	return i
}

// appendErrors adds given errors to the list of errors for the file path
func (c *currentInfos) appendErrors(path string, errors ...string) {
	c.entry(path).appendErrors(errors...)
}

// setPackage sets the position of the "package" statement token
func (c *currentInfos) setPackage(path string, pos token.Pos) {
	c.entry(path).packagePos = pos
}

// setImport sets the position of the "import" statement token and checks to see
// if the error package is already imported making note of it's imported name
func (c *currentInfos) setImport(path string, node *ast.GenDecl) {
	entry := c.entry(path)
	for _, i := range node.Specs {
		imp := i.(*ast.ImportSpec)
		if imp.Path.Value == `"`+errorPackage+`"` {
			// there can be only one import to the error package
			entry.name = imp.Name.Name
		}
	}

	// if there are more than one import statements last one wins
	entry.importNode = node
}

// setPackage sets the position of the "var" statement token
func (c *currentInfos) setVar(path string, node *ast.GenDecl) {
	c.entry(path).varNode = node
}

// allErrors returns all errors for a given package
func (c *currentInfos) allErrors() []string {
	allErrors := make([]string, 0, 10)
	for _, v := range c.info {
		allErrors = append(allErrors, v.errors...)
	}

	return allErrors
}

// current Analyzer scans the package files to gather the current error
// information. We need this first pass to gather positional data and a list of
// defined errors within the package
var current = analysis.Analyzer{
	Name:       "error_current",
	Doc:        "Fetches the currently defined errors",
	Run:        currentErrors,
	Requires:   []*analysis.Analyzer{inspect.Analyzer},
	ResultType: reflect.TypeOf((*currentInfos)(nil)),
}

// errorVariableDecl determines what errors are defined in a "var" statement and
// returns if any are
func errorVariableDecl(pass *analysis.Pass, d ast.Decl) ([]string, bool) {
	var g *ast.GenDecl
	var ok bool

	if g, ok = d.(*ast.GenDecl); !ok || g.Tok != token.VAR {
		return nil, false
	}

	names := make([]string, 0, 5)
	for _, s := range g.Specs {
		var spec *ast.ValueSpec

		if spec, ok = s.(*ast.ValueSpec); !ok {
			continue
		}

		if len(spec.Values) != 1 {
			continue
		}
		val := spec.Values[0]

		if pass.TypesInfo.TypeOf(val).String() != errorPackage+".Error" {
			continue
		}

		if len(spec.Names) != 1 {
			continue
		}

		name := spec.Names[0].Name

		if errorCode.MatchString(name) {
			names = append(names, name)
		}
	}

	if len(names) == 0 {
		return nil, false
	}

	return names, true
}

// name returns the file path for the given File node
func name(pass *analysis.Pass, node *ast.File) string {
	pkg := node.Name.Name
	name := path.Base(pass.Fset.PositionFor(node.Pos(), false).Filename)

	return path.Join(pkg, name)
}

// isTestFile returns true if the provided golang file is a test file
func isTestFile(fileName string) bool {
	return strings.HasSuffix(fileName, "_test.go")
}

// currentErrors scans the package collecting current error and positional
// information
func currentErrors(pass *analysis.Pass) (any, error) {
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	types := []ast.Node{
		(*ast.File)(nil),
	}

	infos := currentInfos{}
	var currentFile string
	inspect.Preorder(types, func(n ast.Node) {
		file := n.(*ast.File)
		currentFile = name(pass, file)

		if isTestFile(currentFile) {
			return
		}

		infos.setPackage(currentFile, file.Name.End())
		for _, d := range file.Decls {
			var g *ast.GenDecl
			var ok bool
			if g, ok = d.(*ast.GenDecl); !ok {
				continue
			}

			switch g.Tok {
			case token.IMPORT:
				infos.setImport(currentFile, g)
			case token.VAR:
				if names, ok := errorVariableDecl(pass, g); ok {
					infos.setVar(currentFile, g)
					infos.appendErrors(currentFile, names...)
				}
			}
		}
	})

	return &infos, nil
}

// returns Analyzer reports any raw errors and suggests fixes to declare new errors
var returns = analysis.Analyzer{
	Name:     "error_returns",
	Doc:      "Makes sure that error handling complies with ec-cli conventions",
	Run:      lintErrors,
	Requires: []*analysis.Analyzer{inspect.Analyzer, &current},
}

// determineCode finds the next error code for a given prefix within the
// provided list of errors
func determineCode(prefix string, errors []string) string {
	next := 0
	for _, e := range errors {
		if v, err := strconv.Atoi(strings.TrimPrefix(e, prefix)); err == nil && v > next {
			next = v
		}
	}

	next++

	return fmt.Sprintf("%s%03d", prefix, next)
}

// problem is a problematic raw error
type problem struct {
	result ast.Expr // original raw error expression
	code   string   // code that we assigned to this error
}

// printNode renders a AST node as string
func printNode(fset *token.FileSet, node any) string {
	var buffy bytes.Buffer
	if err := printer.Fprint(&buffy, fset, node); err != nil {
		panic(err) // existing code should always be printable (FLW)
	}

	code := buffy.String()

	if _, isExpr := node.(ast.Expr); !isExpr && !strings.HasSuffix(code, "\n") {
		// sometimes expressions don't have a trailing newline and we want one
		code += "\n"
	}

	return code
}

// wrapError transforms the provided expression by wrapping it in a
// XXNNN.CausedBy(exp) expression, returns the baked suggestion fix
func wrapError(pass *analysis.Pass, code string, exp ast.Expr) analysis.SuggestedFix {
	wrapped := ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   ast.NewIdent(code),
			Sel: ast.NewIdent("CausedBy"),
		},
		Args: []ast.Expr{
			exp,
		},
	}

	return analysis.SuggestedFix{
		Message: "use errors package",
		TextEdits: []analysis.TextEdit{
			{
				Pos:     exp.Pos(),
				End:     exp.End(),
				NewText: []byte(printNode(pass.Fset, &wrapped)),
			},
		},
	}
}

// declareImport generates import declaration containing already imported
// packages in addition to the error package
func declareImport(current *currentInfo) *ast.GenDecl {
	imports := make([]ast.Spec, 0, 5)
	if current.importNode != nil {
		// there are no import statements at all
		imports = append(imports, current.importNode.Specs...)
	}
	imports = append(imports, &ast.ImportSpec{
		Name: ast.NewIdent("e"),
		Path: &ast.BasicLit{
			Value: `"` + errorPackage + `"`,
		},
	})

	return &ast.GenDecl{
		Tok:   token.IMPORT,
		Specs: imports,
	}
}

func declareErrorVar(errorPackageName, code string) ast.Spec {
	return &ast.ValueSpec{
		Names: []*ast.Ident{
			ast.NewIdent(code),
		},
		Values: []ast.Expr{
			&ast.CallExpr{
				Fun: &ast.SelectorExpr{
					X:   ast.NewIdent(errorPackageName),
					Sel: ast.NewIdent("NewError"),
				},
				Args: []ast.Expr{
					&ast.BasicLit{
						Value: `"` + code + `"`,
					},
					&ast.BasicLit{
						Value: `""`,
					},
					&ast.SelectorExpr{
						X:   ast.NewIdent(errorPackageName),
						Sel: ast.NewIdent("ErrorExitStatus"),
					},
				},
			},
		},
		Comment: &ast.CommentGroup{
			List: []*ast.Comment{
				{
					Text: " // TODO: add message and set the exit status",
				},
			},
		},
	}
}

// report reports linting issue and generates fix suggestions
func report(pass *analysis.Pass, current *currentInfo, problems []problem) {
	if len(problems) == 0 {
		return
	}

	var impNode *ast.GenDecl

	// holds existing variable declarations and any new errors
	var nodes []ast.Spec
	if current.varNode != nil {
		nodes = current.varNode.Specs[:]
	}

	// a diagnostic per raw error code with the fix for the error return
	diagnosis := make([]analysis.Diagnostic, 0, 3)

	// suggestions that we attach to the last diagnostic after we collect all
	// new error variables that need to be declared
	suggestions := make([]analysis.SuggestedFix, 0, 4)

	for _, p := range problems {
		if current.name == "" {
			// the error package is not imported
			impNode = declareImport(current)

			current.name = "e"
		}

		// report raw error linting issue
		diagnosis = append(diagnosis, analysis.Diagnostic{
			Pos:     p.result.Pos(),
			End:     p.result.End(),
			Message: `don't return raw error, return pkg/error.Error`,
			SuggestedFixes: []analysis.SuggestedFix{
				wrapError(pass, p.code, p.result),
			},
		})

		// generate variable declaration for the fix
		nodes = append(nodes, declareErrorVar(current.name, p.code))
	}

	start := current.varStart()
	end := current.varEnd()

	var text string
	if impNode != nil {
		// if we need to add the import for pkg/error add it to the text first
		// so that the variables follow
		text = printNode(pass.Fset, impNode)
		start = current.importStart()
	}

	// group all variables in a signel "var" block
	variable := ast.GenDecl{
		Tok:   token.VAR,
		Specs: nodes,
	}

	text += printNode(pass.Fset, &variable)

	suggestions = append(suggestions, analysis.SuggestedFix{
		Message: "declare the errors",
		TextEdits: []analysis.TextEdit{
			{
				Pos:     start,
				End:     end,
				NewText: []byte(text),
			},
		},
	})

	for i, d := range diagnosis {
		if i == 0 {
			d.SuggestedFixes = append(d.SuggestedFixes, suggestions...)
		}
		pass.Report(d)
	}
}

// lintErrors examines a package looking for any raw errors, i.e. errors that
// are not coded according to pkg/error. Fix suggestions declaring new errors
// replacing those cases are provided
func lintErrors(pass *analysis.Pass) (interface{}, error) {
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	allCurrent := pass.ResultOf[&current].(*currentInfos)

	types := []ast.Node{
		(*ast.File)(nil),
		(*ast.GenDecl)(nil),
		(*ast.ImportSpec)(nil),
		(*ast.ReturnStmt)(nil),
	}

	var errorPrefix string
	var current *currentInfo
	var currentFile string
	var problems = []problem{}

	inspect.Preorder(types, func(n ast.Node) {
		switch node := n.(type) {
		case *ast.File:
			if errorPrefix == "" {
				// calculate an error code prefix to use if there are no
				// existing error variables
				errorPrefix = strings.ToUpper(node.Name.Name[0:2])
			}
			if current != nil {
				// we're on the n+1-th file, report what we have for the n-th
				// file
				report(pass, current, problems)
			}
			// prepare for processing the new file
			currentFile = name(pass, node)

			if isTestFile(currentFile) {
				return
			}

			current = allCurrent.entry(currentFile)
			problems = []problem{}
		case *ast.GenDecl:
			if isTestFile(currentFile) {
				return
			}

			// if the package is using a different prefix we'd like to use it
			// for new errors as well, last one wins
			if names, ok := errorVariableDecl(pass, node); ok {
				errorPrefix = (names[0])[0:2]
			}
		case *ast.ReturnStmt:
			if isTestFile(currentFile) {
				return
			}

			for _, result := range node.Results {
				if pass.TypesInfo.TypeOf(result).String() == "error" {
					// someone has been returning raw errors
					code := determineCode(errorPrefix, allCurrent.allErrors())
					current.appendErrors(code)

					problems = append(problems, problem{result: result, code: code})
				}
			}
		}
	})

	// also report for the last processed file
	report(pass, current, problems)

	return nil, nil
}
