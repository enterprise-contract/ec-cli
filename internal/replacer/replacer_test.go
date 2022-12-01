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

//go:build integration

package replacer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/image"
)

const testDigest = "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"

func TestReplace(t *testing.T) {
	cases := []struct {
		name         string
		images       []string
		sourceFile   string
		sourceSchema string
		overwrite    bool
		expected     string
		err          string
	}{
		{
			name: "replace matches from catalog",
			sourceFile: `
spec:
  pipelineRef:
	bundle: registry.com/catalog/task-one:1.0
	name: simple-build
---
taskRef:
	bundle: registry.com/catalog/task-two:2.0
---
taskRef:
	bundle: registry.com/catalog/task-unknown:3.0
---
bundle-o-landia: registry.com/other/repo@sha256:abc
`,
			expected: `
spec:
  pipelineRef:
	bundle: registry.com/catalog/task-one:1.9@` + testDigest + `
	name: simple-build
---
taskRef:
	bundle: registry.com/catalog/task-two:2.9@` + testDigest + `
---
taskRef:
	bundle: registry.com/catalog/task-unknown:3.0
---
bundle-o-landia: registry.com/other/repo@sha256:abc
`,
		},
		{
			name:   "replace matches from given images",
			images: mockInputImages,
			sourceFile: `
spec:
  pipelineRef:
	bundle: registry.com/some/repo:1.0
	name: simple-build
---
taskRef:
	bundle: registry.com/other/repo:2.0
---
bundle-o-landia: registry.com/other/repo@sha256:abc
`,
			expected: `
spec:
  pipelineRef:
	bundle: registry.com/some/repo:1.9@` + testDigest + `
	name: simple-build
---
taskRef:
	bundle: registry.com/other/repo:2.9@` + testDigest + `
---
bundle-o-landia: registry.com/other/repo:2.9@` + testDigest + `
`,
		},
		{
			name:       "overwrite input file",
			sourceFile: "bundle: registry.com/catalog/task-one:1.0\n",
			overwrite:  true,
			expected:   "bundle: registry.com/catalog/task-one:1.9@" + testDigest + "\n",
		},
		{
			name:         "file schema",
			sourceSchema: "file://",
			sourceFile:   "bundle: registry.com/catalog/task-one:1.0\n",
			expected:     "bundle: registry.com/catalog/task-one:1.9@" + testDigest + "\n",
		},
		{
			name:         "invalid schema",
			sourceSchema: "ftp://",
			err:          "ftp is not a valid source schema",
		},
		{
			name: "invalid image references",
			images: []string{
				// Missing repo, and tag or digest
				"registry.com",
				// Missing tag or digest
				"registry.com/repo",
			},
			err: "2 errors occurred",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hubHttpGet = mockHubHttpGet
			imageParseAndResolve = mockImageParseAndResolve

			sourceFile := path.Join(t.TempDir(), "source.yaml")
			err := ioutil.WriteFile(sourceFile, []byte(c.sourceFile), 0777)
			assert.NoError(t, err)
			opts := &CatalogOptions{
				CatalogName: mockCatalogName,
				RepoBase:    mockCatalogRepoBase,
				HubAPIURL:   "https://api.example.com",
			}
			got, err := Replace(context.TODO(), c.images, c.sourceSchema+sourceFile, c.overwrite, opts)
			if c.err != "" {
				assert.ErrorContains(t, err, c.err)
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, c.expected, string(got))

			sourceFileContents, err := ioutil.ReadFile(sourceFile)
			assert.NoError(t, err)
			var expectedSourceFileContents string
			if c.overwrite {
				expectedSourceFileContents = c.expected
			} else {
				expectedSourceFileContents = c.sourceFile
			}
			assert.Equal(t, expectedSourceFileContents, string(sourceFileContents))
		})
	}
}

func TestReplaceGitRepo(t *testing.T) {
	cases := []struct {
		name           string
		source         string
		overwrite      bool
		expectedBranch string
	}{
		{
			name:           "https schema",
			expectedBranch: "main",
			source:         "https://git.example.com/org/repo",
		},
		{
			name:           "http schema",
			expectedBranch: "main",
			source:         "http://git.example.com/org/repo",
		},
		{
			name:           "git schema",
			expectedBranch: "main",
			source:         "git://git@example.com:org/repo.git",
		},
		{
			name:           "overwrite is ignored",
			expectedBranch: "main",
			source:         "https://git.example.com/org/repo",
			overwrite:      true,
		},
		{
			name:           "explicit branch",
			expectedBranch: "my-branch",
			source:         "https://git.example.com/org/repo#my-branch",
		},
		{
			name:           "explicit branch",
			expectedBranch: "my-odd#branch",
			source:         "https://git.example.com/org/repo#my-odd#branch",
		},
		{
			name:           "trailing '#' defaults to main",
			expectedBranch: "main",
			source:         "https://git.example.com/org/repo#",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gitRepoLayout := map[string]string{
				"input.yaml": `
bundle-o-landia: registry.com/other/repo@sha256:abc
`,
				".tekton/pipeline.yaml": `
spec:
  pipelineRef:
	bundle: registry.com/catalog/task-one:1.0
	name: simple-build
`,
				".tekton/task.yml": `
spec:
  taskRef:
    bundle: registry.com/catalog/task-two:2.0
`,
				".tekton/unknown-task.yml": `
spec:
  taskRef:
	bundle: registry.com/catalog/task-unknown:3.0
`,
				"ignore-not-yaml.txt": `
bundle: registry.com/catalog/task-one:1.0
`,
				"empty/dir/is/ignored/": ``,
			}

			expected := `diff --git a/.tekton/pipeline.yaml b/.tekton/pipeline.yaml
index 7bbff0e..47d4711 100755
--- a/.tekton/pipeline.yaml
+++ b/.tekton/pipeline.yaml
@@ -1,5 +1,5 @@

 spec:
   pipelineRef:
-	bundle: registry.com/catalog/task-one:1.0
+	bundle: registry.com/catalog/task-one:1.9@` + testDigest + `
 	name: simple-build
diff --git a/.tekton/task.yml b/.tekton/task.yml
index 837cf14..48e4035 100755
--- a/.tekton/task.yml
+++ b/.tekton/task.yml
@@ -1,4 +1,4 @@

 spec:
   taskRef:
-    bundle: registry.com/catalog/task-two:2.0
+    bundle: registry.com/catalog/task-two:2.9@` + testDigest + `
diff --git a/empty/dir/is/ignored/ b/empty/dir/is/ignored/
deleted file mode 100755
index e69de29..0000000
diff --git a/input.yaml b/input.yaml
index 76af797..b6a3c56 100755
--- a/input.yaml
+++ b/input.yaml
@@ -1,2 +1,2 @@

-bundle-o-landia: registry.com/other/repo@sha256:abc
+bundle-o-landia: registry.com/other/repo:2.9@` + testDigest + `
`
			hubHttpGet = mockHubHttpGet
			imageParseAndResolve = mockImageParseAndResolve
			cloneRepo = mockCloneRepo(gitRepoLayout, c.expectedBranch)

			opts := &CatalogOptions{
				CatalogName: mockCatalogName,
				RepoBase:    mockCatalogRepoBase,
				HubAPIURL:   "https://api.example.com",
			}
			got, err := Replace(context.TODO(), mockInputImages, c.source, c.overwrite, opts)
			assert.NoError(t, err)
			assert.Equal(t, fixDiffFormat(expected), string(got))
		})
	}
}

var emptyLine = regexp.MustCompile("(?m)^$")

// fixDiffFormat returns a copy of the given diff in a more correct
// diff format.
//
// The diff format turns empty lines into a line containing a single
// space. However, most text editors will strip off these single spaces.
// To make it easier to write test cases, replace each empty line to
// with a single white space. The exception is, of course, the last
// line, which is indeed expected to be empty.
func fixDiffFormat(diff string) string {
	return strings.Join(emptyLine.Split(diff, -1), " ")
}

const mockCatalogRepoBase = "registry.com/catalog/"
const mockCatalogName = "my-catalog"

var mockInputImages = []string{
	"registry.com/unmentioned/repo:0.9@" + testDigest,
	"registry.com/some/repo:1.9@" + testDigest,
	"registry.com/other/repo:2.9@" + testDigest,
}

var mockCatalogVersions = map[string]string{
	mockCatalogName + ":task:task-one": "1.9",
	mockCatalogName + ":task:task-two": "2.9",
}

func mockHubHttpGet(url string) (resp *http.Response, err error) {
	urlParts := strings.Split(url, "/")
	key := strings.Join(urlParts[len(urlParts)-3:], ":")
	version := mockCatalogVersions[key]
	if version == "" {
		return nil, errors.New("not found")
	}
	content := []byte(
		fmt.Sprintf(`{"data": {"latestVersion": {"version": "%s"}}}`, version))
	body := ioutil.NopCloser(bytes.NewReader([]byte(content)))
	return &http.Response{
		StatusCode: 200,
		Body:       body,
	}, nil
}

func mockImageParseAndResolve(url string, opts ...name.Option) (*image.ImageReference, error) {
	// Adding a digest makes it so the real image.ParseAndResolve doesn't make
	// a network connection.
	return image.ParseAndResolve(url+"@"+testDigest, opts...)
}

func mockCloneRepo(layout map[string]string, expectedBranch string) func(context.Context, string, bool, *git.CloneOptions) (*git.Repository, error) {
	// func(path string, layout map[string]string) error {
	return func(_ context.Context, dir string, _ bool, opts *git.CloneOptions) (*git.Repository, error) {

		branch := opts.ReferenceName.String()
		if opts.ReferenceName.String() != "refs/heads/"+expectedBranch {
			return nil, fmt.Errorf("expected branch %q, got %q", expectedBranch, branch)
		}
		// Create an empty git repository, not bare
		repo, err := git.PlainInit(dir, false)
		if err != nil {
			return nil, err
		}

		worktree, err := repo.Worktree()
		if err != nil {
			return nil, err
		}

		// Create all the files on disk
		for relativePath, content := range layout {
			fullPath := filepath.Join(dir, relativePath)
			dir, _ := filepath.Split(fullPath)
			if err := os.MkdirAll(dir, 0777); err != nil {
				return nil, err
			}
			if err := ioutil.WriteFile(fullPath, []byte(content), 0777); err != nil {
				return nil, err
			}
			if _, err := worktree.Add(relativePath); err != nil {
				return nil, err
			}
		}

		// Create a git config for deterministic execution
		gitConfig := []byte(`
[user]
    name = EC CLI
    email = ec-cli@redhat.com
`)
		if err := ioutil.WriteFile(path.Join(dir, ".git", "config"), gitConfig, 0777); err != nil {
			return nil, err
		}

		// Commit changes to create the first commit
		_, err = worktree.Commit("Initialize repository", &git.CommitOptions{All: true})
		if err != nil {
			return nil, err
		}

		return repo, nil
	}
}
