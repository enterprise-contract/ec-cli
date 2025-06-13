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

package tracker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	gba "github.com/Maldris/go-billy-afero"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/utils"
)

type gitTracker struct {
	repositories *sync.Map
}

func NewGitTracker() *gitTracker {
	g := gitTracker{}
	g.repositories = &sync.Map{}

	return &g
}

func (g gitTracker) Close(ctx context.Context) {
	fs := utils.FS(ctx)

	g.repositories.Range(func(_, val any) bool {
		r, err := val.(func() (*git.Repository, error))()
		if err != nil {
			return true
		}

		bfs := r.Storer.(*filesystem.Storage).Filesystem()

		// ignore error
		_ = fs.RemoveAll(bfs.Root())

		return true
	})
}

func clone(ctx context.Context, repository string) (*git.Repository, error) {
	fs := utils.FS(ctx)
	tmpdir, err := afero.TempDir(fs, "", "ec-git")
	if err != nil {
		return nil, err
	}

	bfs, err := gba.New(fs, "", false).Chroot(tmpdir)
	if err != nil {
		return nil, err
	}

	s := filesystem.NewStorage(bfs, cache.NewObjectLRUDefault())

	opts := git.CloneOptions{
		URL:        strings.TrimPrefix(repository, "git+"),
		NoCheckout: true,
	}

	// set by acceptance tests
	if os.Getenv("GIT_SSL_NO_VERIFY") == "true" {
		opts.InsecureSkipTLS = true
	}

	return git.CloneContext(ctx, s, bfs, &opts)
}

func (g *gitTracker) GitResolve(ctx context.Context, repository, path string) (string, error) {
	cfn := func() (*git.Repository, error) {
		return clone(ctx, repository)
	}
	rfn, _ := g.repositories.LoadOrStore(repository, sync.OnceValues(cfn))

	r, err := rfn.(func() (*git.Repository, error))()
	if err != nil {
		return "", err
	}

	commits, err := r.Log(&git.LogOptions{
		FileName: &path,
		Order:    git.LogOrderCommitterTime,
	})
	if err != nil {
		return "", err
	}
	defer commits.Close()

	var c *object.Commit
outer:
	for {
		c, err = commits.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", fmt.Errorf("unable to find any commits for path: %q", path)
			}
			return "", err
		}

		if c == nil {
			break
		}

		noParents := c.NumParents()
		if noParents == 0 {
			// initial commit
			if _, err := c.File(path); err != nil && err != object.ErrFileNotFound {
				return "", err
			}

			return c.ID().String(), nil
		} else if noParents == 1 {
			// first commit with only one parent is a non-merge commit, even though
			// a merge commit is a valid commit id for a change on the path we want
			// to filter out the merge commits as the default UIs in GitHub
			// (GitLab?) do not show the merge commits in the file history views
			parent, err := c.Parent(0)
			if err != nil {
				return "", err
			}
			// we get commits that didn't change the path, so filter to only
			// those that did
			p, _ := parent.Patch(c)
			for _, f := range p.FilePatches() {
				from, to := f.Files()
				if (from != nil && to != nil && from.Path() == path) || (to != nil && to.Path() == path) {
					// the first commit that did change the file is the latest
					// for that file
					break outer
				}
			}
		}
	}

	if c == nil {
		return "", fmt.Errorf("unable to find any commits for path: %q", path)
	}

	return c.ID().String(), nil
}
