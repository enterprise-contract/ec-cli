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

// Package git creates a stub git repository available over HTTP. The repositories
// are available on localhost:`port`/git/`name`.git, the host and port
// can be obtained from Host
package git

import (
	"context"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/cucumber/godog"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/hacbs-contract/ec-cli/acceptance/log"
	"github.com/hacbs-contract/ec-cli/acceptance/testenv"
)

type key int

const gitStateKey = key(0) // we store the gitState struct under this key in Context and when persisted

type gitState struct {
	HostAndPort     string
	RepositoriesDir string
}

func (g gitState) Key() any {
	return gitStateKey
}

func (g gitState) Up() bool {
	return g.HostAndPort != "" && g.RepositoriesDir != ""
}

// startStubGitServer launches a stub git server and exposes the port via NAT from the container
func startStubGitServer(ctx context.Context) (context.Context, error) {
	var state *gitState
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if state.Up() {
		return ctx, nil
	}

	// the directory on the host where we'll store the git repositories
	repositories, err := os.MkdirTemp("", "git.*")
	if err != nil {
		return ctx, err
	}

	req := testenv.TestContainersRequest(ctx, testcontainers.ContainerRequest{
		Image:        "docker.io/ynohat/git-http-backend",
		ExposedPorts: []string{"80/tcp"},
		WaitingFor:   wait.ForListeningPort("80/tcp"),
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

	port, err := git.MappedPort(ctx, "80/tcp")
	if err != nil {
		return ctx, err
	}

	state.HostAndPort = fmt.Sprintf("localhost:%d", port.Int())
	state.RepositoriesDir = repositories

	return ctx, nil
}

// Host returns the `host:port` of the git server. The repository can be accessed
// via http://host:port/git/`name`git
func Host(ctx context.Context) string {
	return testenv.FetchState[gitState](ctx).HostAndPort
}

func IsRunning(ctx context.Context) bool {
	if !testenv.HasState[gitState](ctx) {
		return false
	}

	state := testenv.FetchState[gitState](ctx)
	return state.Up()
}

// createGitRepository uses go-git to initialize a git repository on the bound
// repositories directory, copies given files and commits them
func createGitRepository(ctx context.Context, repositoryName string, files *godog.Table) error {
	state := testenv.FetchState[gitState](ctx)

	repositoryDir := path.Join(state.RepositoriesDir, repositoryName+".git")

	if s, _ := os.Stat(repositoryDir); s != nil && s.IsDir() {
		// repository already exists
		return nil
	}

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

		b, err := os.ReadFile(path.Join("acceptance", source))
		if err != nil {
			return err
		}

		err = os.WriteFile(dest, b, 0644)
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

		var state *gitState
		if ctx, err := testenv.SetupState(ctx, &state); err != nil {
			return ctx, err
		}

		if !state.Up() {
			return ctx, nil
		}

		os.RemoveAll(state.RepositoriesDir)

		return ctx, nil
	})
}
