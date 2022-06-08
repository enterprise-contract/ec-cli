package git

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/google/go-github/v42/github"
	"golang.org/x/oauth2"
)

type GithubAuth struct {
	Token string
}

type gitClient struct {
	Client *github.Client
}

type RepositoryShort struct {
	Repo string
}

type Commit struct {
	Commit *github.Commit `json:"commit,omitempty"`
}

type jiraReference struct {
	JiraIds []string `json:"jiraIds,omitempty"`
}

// Connect to github
// It returns a gitClient
func (a GithubAuth) Connect(ctx context.Context) gitClient {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: a.Token},
	)
	tc := oauth2.NewClient(ctx, ts)

	return gitClient{
		Client: github.NewClient(tc),
	}
}

// GetCommit gets a commit from github
// It returns the commit
func (c gitClient) GetCommit(ctx context.Context, repository, commit string) (Commit, error) {
	orgName, repoName, err := splitRepo(repository)
	if err != nil {
		return Commit{}, err
	}

	repo, _, err := c.Client.Repositories.GetCommit(
		ctx,
		orgName,
		repoName,
		commit,
		&github.ListOptions{PerPage: 10},
	)
	if err != nil {
		return Commit{}, err
	}

	return Commit{
		Commit: repo.GetCommit(),
	}, nil
}

// splitRepo splits a a repository in the form organization/repository
// It returns the organization and repository as separate strings
func splitRepo(repo string) (string, string, error) {
	val := strings.Split(repo, "/")
	if len(val) != 2 {
		return "", "", errors.New(
			"the repository argument was in the wrong format. Format should be organization/repository.",
		)
	}
	return val[0], val[1], nil
}

// MatchJira finds a Jira id in a git commit message
// It returns the Jira id
func (c Commit) MatchJira(jiraMatch string) (jiraReference, error) {
	var jiras []string
	re := regexp.MustCompile(jiraMatch)
	match := re.FindStringSubmatch(c.Commit.GetMessage())
	if len(match) < 1 {
		return jiraReference{}, errors.New(
			"there were no jira references found.",
		)
	}
	jiras = append(jiras, match[1])
	return jiraReference{JiraIds: jiras}, nil
}
