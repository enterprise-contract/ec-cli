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

// Creates a stub git repository available over HTTP. The repositories
// are available on localhost:`port`/git/`name`.git, the host and port
// can be obtained from GitHost
package git

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/cucumber/godog"
	"github.com/docker/go-connections/nat"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/log"
	"github.com/hacbs-contract/ec-cli/internal/acceptance/testenv"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type key int

const (
	gitHostKey         key = iota // we store the host:port under this in the Context
	gitRepositoriesKey            // key to the path to the TEMP directory mounted in the git server container in the Context
)

// startStubGitServer launches a stub git server and exposes the port via NAT from the container
func startStubGitServer(ctx context.Context) (context.Context, error) {
	// the directory on the host where we'll store the git repositories
	repositories, err := os.MkdirTemp("", "git.*")
	if err != nil {
		return ctx, err
	}

	req := testenv.TestContainersRequest(ctx, testcontainers.ContainerRequest{
		Image:        "docker.io/ynohat/git-http-backend",
		ExposedPorts: []string{"80/tcp"},
		WaitingFor:   wait.ForListeningPort(nat.Port("80/tcp")),
		Binds: []string{
			fmt.Sprintf("%s:/git:Z", repositories), // :Z is to allow accessing the directory under SELinux
		},
	})

	git, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           log.LoggerFor(ctx),
	})
	if err != nil {
		return ctx, err
	}

	port, err := git.MappedPort(ctx, nat.Port("80/tcp"))
	if err != nil {
		return ctx, err
	}

	ctx = context.WithValue(ctx, gitHostKey, fmt.Sprintf("localhost:%d", port.Int()))
	ctx = context.WithValue(ctx, gitRepositoriesKey, repositories)

	return ctx, nil
}

// GitHost returns the `host:port` of the git server. The repository can be accessed
// via http://host:port/git/`name`git
func GitHost(ctx context.Context) string {
	return ctx.Value(gitHostKey).(string)
}

// createGitRepository uses go-git to initialize a git repository on the bound
// repositories directory, copies given files and commits them
func createGitRepository(ctx context.Context, repositoryName string, files *godog.Table) error {
	repositoryDir := path.Join(ctx.Value(gitRepositoriesKey).(string), repositoryName+".git")

	// create a storage for the .git directory within repositoryDir
	dotGit := filesystem.NewStorage(osfs.New(path.Join(repositoryDir, ".git")), cache.NewObjectLRUDefault())
	// filesystem to hold the policy files
	worktree := osfs.New(repositoryDir)

	// perform a `git init``
	r, err := git.Init(dotGit, worktree)
	if err != nil {
		return err
	}

	w, err := r.Worktree()
	if err != nil {
		return err
	}

	// copy all files, expects a table rows with target and source cells (in that order)
	for _, row := range files.Rows {
		file := row.Cells[0].Value

		dest := path.Join(repositoryDir, file)
		source := row.Cells[1].Value

		b, err := ioutil.ReadFile(source)
		if err != nil {
			return err
		}

		err = ioutil.WriteFile(dest, b, 0644)
		if err != nil {
			return err
		}

		_, err = w.Add(file)
		if err != nil {
			return err
		}
	}

	// do a `git commit`
	_, err = w.Commit("test data", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Testy McTestface",
			Email: "test@test.test",
			When:  time.Now(),
		},
	})
	if err != nil {
		return err
	}

	return nil
}

// AddStepsTo adds Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^stub git daemon running$`, startStubGitServer)
	sc.Step(`^a git repository named "([^"]*)" with$`, createGitRepository)

	// removes all git repositories from the filesystem
	sc.After(func(ctx context.Context, finished *godog.Scenario, scenarioErr error) (context.Context, error) {
		if testenv.Persisted(ctx) {
			return ctx, nil
		}

		repositories := ctx.Value(gitRepositoriesKey)

		if repositories == nil {
			return ctx, nil
		}

		os.RemoveAll(repositories.(string))

		return ctx, nil
	})
}
