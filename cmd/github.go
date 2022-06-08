/*
Copyright © 2022 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/hacbs-contract/ec-cli/pkg/git"
	"github.com/spf13/cobra"
)

var githubCmd = &cobra.Command{
	Use:   "github",
	Short: "Interact with the github api",
	Long: `Interact with the github api. Supported commands are getting a commit
	and parsing a jira id from a commit message`,
	Run: func(cmd *cobra.Command, args []string) {
		flagCommit, _ := cmd.Flags().GetString("commit")
		flagJira, _ := cmd.Flags().GetBool("jira")
		flagJiraMatch, _ := cmd.Flags().GetString("jiraMatch")

		if flagCommit != "" {
			commit, err := getCommit()
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(-1)
			}
			if flagJira {
				jiraId, err := commit.MatchJira(flagJiraMatch)
				if err != nil {
					fmt.Println(err.Error())
					os.Exit(-1)
				}
				jiraJson, _ := json.Marshal(jiraId)
				fmt.Printf("%s\n", jiraJson)
			} else {
				commitJson, _ := json.Marshal(commit)
				fmt.Printf("%s\n", commitJson)
			}
		}
	},
}

var commit, token, repository, jiraMatch string
var jira bool

func init() {
	rootCmd.AddCommand(githubCmd)
	githubCmd.Flags().StringVar(&commit, "commit", "", "Return the commit information")
	githubCmd.Flags().BoolVar(&jira, "jira", false, "Parse Jira id from the commit message")
	githubCmd.Flags().StringVar(&jiraMatch, "jiraMatch", "(?i)RedHat JIRA Issue: ([a-zA-Z]+-\\d+)", "Regex to match Jira id with")
	githubCmd.Flags().StringVar(&token, "token", "", "The github api token to use")
	githubCmd.Flags().StringVar(&repository, "repository", "", "The github repository. Format: organization/repository")
}

// getCommit connects to github and fetches a commit.
// It returns a commit
func getCommit() (git.Commit, error) {
	ctx := context.Background()
	auth := git.GithubAuth{
		Token: token,
	}
	client := auth.Connect(ctx)
	return client.GetCommit(ctx, repository, commit)
}
