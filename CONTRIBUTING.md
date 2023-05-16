# Contributing

Enterprise Contract welcomes contributions in many forms. [Pull requests](https://docs.github.com/en/get-started/quickstart/github-glossary#pull-request) are specifically appreciated and the maintainers will make every effort to assist with any issues in the pull request discussion. Feel free to create a pull request even if you are new to the process. If you need more information, see [this article](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request) about how creating a pull request.

## Code of Conduct

Our [company values](https://www.redhat.com/en/about/brand/standards/culture) guide us in our day-to-day interactions and decision-making. Our open source projects are no exception and they will define the standards for how to engage with the project through a [code of conduct](/CODE_OF_CONDUCT.md).

Please, make sure you read both of them before contributing, so you can help us to maintain a healthy community.

## Requesting Support

Before you ask a question, it is best to search for existing [issues](https://github.com/enterprise-contract/ec-cli/issues) that might help you. In case you have found a suitable issue and still need clarification, you can write your question in this issue. It is also advisable to search the internet for answers first.

If you then still feel the need to ask a question and need clarification, we recommend the following:

* Open an [issue](https://github.com/enterprise-contract/ec-cli/issues/new).
* Provide as much context as you can about what you’re running into.
* Provide project and platform versions (golang, operator-sdk, etc), depending on what seems relevant.

The community will then take care of the issue as soon as possible.

## Reporting Issues

We use GitHub issues to track bugs and errors. If you run into an issue with the project:

* Open an Issue.
* Explain the behavior you would expect and the actual behavior.
* Please provide as much context as possible and describe the reproduction steps that someone else can follow to recreate the issue on their own. This usually includes your code. For good bug reports you should isolate the problem and create a reduced test case.

Once it’s filed:

* The project team will label the issue accordingly.
* A team member will try to reproduce the issue with your provided steps. 
  * If there are no reproduction steps or no obvious way to reproduce the issue, the team will ask you for those steps and mark the issue as `needs-reproducer`. Bugs with this tag will not be addressed until they are reproduced.
* If the team is able to reproduce the issue, it will be marked `needs-fix` and left to be implemented by someone. Other labels can be used in addition to better describe the issue or its criticality.

## Requesting Features

Enhancement suggestions are tracked as GitHub issues.

* Suggest a single enhancement per issue.
* Provide a clear and descriptive title for the issue to identify what the specific suggestion is.
* Provide a step-by-step description of the suggested enhancement in as much detail as possible.
* Describe the current behavior, the expected one, and why you expect this behavior.
  * At this point you can also list which alternatives do not work for you.
* Explain why this enhancement would be useful to other users.
  * You may also want to point out the other projects that solved it "better" and could serve as inspiration.

## Submitting Changes

Before contributing code or documentation to this project, make sure you read the following sections.

### Commit message standards

The commit message should contain an overall explanation about the change and the motivation behind it. Please note that mentioning a Jira ticket ID or a GitHub issue, isn't a replacement for that.

### Signing Commits

All commits must be signed-off

### Pull Requests

All changes must come from a pull request (PR) and cannot be directly committed. While anyone can engage in activity on a PR, pull requests are only approved by team members.

Before a pull request can be merged:

* The content of the PR has to be relevant to the PR itself
* The contribution must follow the style guidelines of this project
* Multiple commits should be used if the PR is complex and clarity can be improved, but they should still relate to a single topic
* For code contributions, tests have to be added/modified to ensure the code works
* There has to be at least one approval
* The feature branch must be rebased so it contains the latest changes from the target branch
* The CI has to pass successfully
* Every comment has to be addressed and resolved
