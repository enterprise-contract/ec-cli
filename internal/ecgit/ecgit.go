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

package ecgit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v45/github"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	giturls "github.com/whilp/git-urls"
	"golang.org/x/oauth2"

	"github.com/hacbs-contract/ec-cli/internal/utils"
)

var CloneRepoWithAuth = cloneRepoWithAuth
var CreateAutomatedPR = createAutomatedPR
var CreateBranch = createBranch
var CreatePullRequest = createPullRequest
var ApplyDiff = applyDiff
var CommitChange = commitChange
var PushChange = pushChange
var NewGithubClient = newGithubClient

// cloneRepoWithAuth clones the specified repository.
func cloneRepoWithAuth(ctx context.Context, repoURL string, destDir string) (*git.Repository, error) {
	log.Info("No private key file provided, using default authentication")
	if os.Getenv("GITHUB_USERNAME") == "" {
		log.Debug("Unable to clone repository, GITHUB_USERNAME not set")
		return nil, errors.New("GITHUB_USERNAME not set")
	}
	if os.Getenv("GITHUB_TOKEN") == "" {
		log.Debug("Unable to clone repository, GITHUB_TOKEN not set")
		return nil, errors.New("GITHUB_TOKEN not set")
	}
	auth := &http.BasicAuth{
		Username: os.Getenv("GITHUB_USERNAME"),
		Password: os.Getenv("GITHUB_TOKEN"),
	}

	r, err := git.PlainCloneContext(ctx, destDir, false, &git.CloneOptions{
		Auth:     auth,
		URL:      repoURL,
		Progress: os.Stdout,
	})
	if err != nil {
		log.Debug("Unable to clone repository due to error")
		return nil, err
	}
	return r, nil
}

// createBranch creates a new branch on the specified repository.
func createBranch(repo *git.Repository, branchName string) (*git.Worktree, error) {
	// Create a new branch
	headRef, err := repo.Head()
	if err != nil {
		log.Debug("Unable to create branch due to getting HEAD ref")
		return nil, err
	}
	refName := plumbing.NewBranchReferenceName(branchName)
	ref := plumbing.NewHashReference(refName, headRef.Hash())
	err = repo.Storer.SetReference(ref)
	if err != nil {
		log.Debugf("Error setting ref: %s\n", ref)
		return nil, err
	}
	w, err := repo.Worktree()
	if err != nil {
		log.Debug("Unable to get repo worktree")
		return nil, err
	}
	err = w.Checkout(&git.CheckoutOptions{
		Branch: plumbing.ReferenceName(refName.String()),
	})
	if err != nil {
		log.Debugf("Error checking out branch: %s\n", refName.String())
		return nil, err
	}
	return w, nil
}

// applyDiff applies the diff to the specified repository.
func applyDiff(repoPath string, diffFilePath string) error {
	err := exec.Command("git", "-C", repoPath, "apply", diffFilePath).Run()
	if err != nil {
		log.Debugf("Error applying diff file '%s'\n", diffFilePath)
		return err
	}
	return nil
}

// commitChange commits the changes in the worktree to the specified repository.
func commitChange(repo *git.Repository, refName string, message string) (*object.Commit, error) {
	w, err := repo.Worktree()
	if err != nil {
		log.Debug("Error getting repo worktree")
		return nil, err
	}
	commit, err := w.Commit(message, &git.CommitOptions{
		All: true,
	})
	if err != nil {
		log.Debug("Error creating commit in worktree")
		return nil, err
	}
	obj, err := repo.CommitObject(commit)
	if err != nil {
		log.Debug("Error creating commit object")
		return nil, err
	}
	return obj, nil
}

// pushChange pushes the changes to the specified repository.
func pushChange(path string) error {
	if os.Getenv("GITHUB_TOKEN") == "" {
		log.Debug("Unable to push changes")
		return errors.New("GITHUB_TOKEN not set")
	}
	if os.Getenv("GITHUB_USERNAME") == "" {
		log.Debug("Unable to push changes")
		return errors.New("GITHUB_USERNAME not set")
	}
	r, err := git.PlainOpen(path)
	if err != nil {
		log.Debugf("Unable to open repository in '%s'", path)
		return err
	}
	auth := &http.BasicAuth{
		Username: os.Getenv("GITHUB_USERNAME"),
		Password: os.Getenv("GITHUB_TOKEN"),
	}
	err = r.Push(&git.PushOptions{
		Auth:  auth,
		Force: true,
	})
	if err != nil {
		log.Debug("Unable to push changes")
		return err
	}

	return nil
}

// createPullRequest creates a new pull request on the specified repository.
func createPullRequest(ctx context.Context, client *github.Client, targetRepoOwner string, targetRepoName string, pr *github.NewPullRequest) (htmlurl string, err error) {
	newPr, _, err := client.PullRequests.Create(ctx, targetRepoOwner, targetRepoName, pr)
	if err != nil {
		log.Debug("Unable to create pull request")
		return htmlurl, err
	}
	htmlurl = newPr.GetHTMLURL()
	return
}

// newGithubClient creates a new GitHub client.
func newGithubClient(ctx context.Context) (*github.Client, error) {
	if os.Getenv("GITHUB_TOKEN") == "" {
		log.Debug("Unable to create GitHub client")
		return nil, errors.New("GITHUB_TOKEN not set")
	}
	token := os.Getenv("GITHUB_TOKEN")
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)

	return github.NewClient(tc), nil
}

// parseRepoURL parses the specified GitHub url and returns owner, repo name, http URL and error
func parseRepoURL(repoURL string) (repoOwner string, repoName string, repoHTTP string, err error) {
	repoURLParsed, err := giturls.Parse(repoURL)
	if err != nil {
		log.Debug("Unable to parse repo URL")
		return
	}
	repoOwner = strings.Split(repoURLParsed.Path, "/")[1]
	repoName = strings.Split(repoURLParsed.Path, "/")[2]
	repoHTTP = fmt.Sprintf("https://%s/%s/%s", repoURLParsed.Host, repoOwner, repoName)
	return
}

// createAutomatedPR executes the workflow to clone, create the specified branch, apply a diff file, commit the changes
// push the changes to the repo remote and create a PR for the changes.
func createAutomatedPR(ctx context.Context, componentRepoURL string, diffFilePath string, destinationBranch string, prBranchName string, prTitle string, prBody string) error {
	ok, err := afero.Exists(utils.AppFS, diffFilePath)
	if err != nil {
		log.Debug("Unable to check if diff file exists")
		return err
	} else if !ok {
		log.Debug("Diff file does not exist")
		return fmt.Errorf("diff file '%s' does not exist", diffFilePath)
	}
	destDir, err := utils.CreateWorkDir()
	if err != nil {
		log.Errorf("Error creating working directory: %s\n", err)
		return err
	}
	defer func() {
		err = utils.AppFS.RemoveAll(destDir)
		if err != nil {
			log.Fatal(err)
		}
	}()
	log.Debugf("Created working directory: %s\n", destDir)

	repoOwner, repoName, repoURL, err := parseRepoURL(componentRepoURL)
	if err != nil {
		return err
	}

	repo, err := cloneRepoWithAuth(ctx, repoURL, destDir)
	if err != nil {
		log.Debugf("Error cloning repository: %s\n", repoURL)
		return err
	}
	log.Debugf("Cloned '%s' into '%s'\n", repoURL, destDir)

	_, err = createBranch(repo, prBranchName)
	if err != nil {
		log.Debugf("Error creating branch: %s\n", prBranchName)
		return err
	}
	log.Debugf("Created branch '%s'\n", prBranchName)

	err = applyDiff(destDir, diffFilePath)
	if err != nil {
		log.Debugf("Unable to apply patch file: %s\n", diffFilePath)
		return fmt.Errorf("unable to apply patch file: %w", err)
	}
	log.Debugf("Applied diff file '%s' to repo in %s\n", diffFilePath, destDir)

	commit, err := commitChange(repo, prBranchName, "This is an automated change")
	if err != nil {
		log.Debug("Unable to commit change")
		return err
	}
	log.Debugf("Committed changes to %s\n", prBranchName)
	log.Debugf("Commit hash: %s\n", commit.Hash)

	err = pushChange(destDir)
	if err != nil {
		log.Debugf("Unable to push change")
		return err
	}
	log.Debug("Pushed changes successfully")

	ghClient, err := newGithubClient(ctx)
	if err != nil {
		log.Debugf("Uanble to create github client")
		return err
	}

	newPR := &github.NewPullRequest{
		Title:               github.String(prTitle),
		Head:                github.String(prBranchName),
		Base:                github.String(destinationBranch),
		Body:                github.String(prBody),
		MaintainerCanModify: github.Bool(true),
	}
	prURL, err := createPullRequest(ctx, ghClient, repoOwner, repoName, newPR)
	if err != nil {
		log.Debugf("Unable to create PR")
		return err
	}
	fmt.Printf("Created pull request: %s\n", prURL)
	if err != nil {
		log.Debug("Unable to display PullRequest URL on stdout")
		return err
	}
	log.Debugf("Created pull request: %s\n", prURL)
	return nil
}
