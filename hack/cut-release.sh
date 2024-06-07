#!/usr/bin/env bash
# Copyright The Enterprise Contract Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ $CURRENT_BRANCH != "main" ]]; then
	echo "Expecting to be in main branch!"
	exit 1
fi

RELEASE_NAME="v$(cat VERSION)"
if [[ $RELEASE_NAME != *.* || $RELEASE_NAME == *.*.* ]]; then
	echo "Release name should include one dot, e.g. v0.5 or v1.1-candidate"
	exit 1
fi

# Use release name as-is for the branch name
BRANCH_NAME="release-${RELEASE_NAME}"

# Konflux disallows . chars in names so remove those
KONFLUX_APPLICATION_SUFFIX="${RELEASE_NAME/./}"

# Could be whatever, but let's adopt a consistent convention
KONFLUX_APPLICATION_NAME=ec-${KONFLUX_APPLICATION_SUFFIX}
KONFLUX_CLI_COMPONENT_NAME=cli-${KONFLUX_APPLICATION_SUFFIX}

# Show some useful values
echo Release name: $RELEASE_NAME
echo Release branch name: $BRANCH_NAME
echo Konflux application name: $KONFLUX_APPLICATION_NAME
echo Konflux cli component name: $KONFLUX_CLI_COMPONENT_NAME

KONFLUX_APPS_URL=https://console.redhat.com/preview/application-pipeline/workspaces/rhtap-contract/applications

nice_title() {
	echo -e "\033[1m» $*\033[0m"
}

# Explain what needs to be done next
# This is like slightly interactive documentation.
# (We could make this more automated in future.)
cat <<EOT1
Next steps:

$(nice_title Create new release branch)

git fetch upstream
git push upstream refs/remotes/upstream/main:refs/heads/${BRANCH_NAME}
git checkout -b ${BRANCH_NAME} upstream/${BRANCH_NAME}

$(nice_title Create new application in Konflux)

Login at ${KONFLUX_APPS_URL}
Click "Create application"
  Application name: ${KONFLUX_APPLICATION_NAME}
Click "Add component"
  Git repository url: https://github.com/enterprise-contract/ec-cli
  Git reference: ${BRANCH_NAME} (under "Advanced Options")
  Dockerfile: Dockerfile.dist
  Component name: ${KONFLUX_CLI_COMPONENT_NAME}
  Pipeline: docker-build
Click "Create application" to submit

$(nice_title Wait for Konflux to generate its pipeline definition PR)

The PR should appear at https://github.com/enterprise-contract/ec-cli/pulls
Wait for the PR to pass the ${KONFLUX_CLI_COMPONENT_NAME}-on-pull-request check
You can also find the pipeline run at ${KONFLUX_APPS_URL}/${KONFLUX_APPLICATION_NAME}/activity/pipelineruns
When it's done you can merge, or you can leave it unmerged and push more commits to it shortly.
(Either way you can continue to next section while you're waiting.)

EOT1

# (Breaking up the long heredoc)
cat <<EOT2
$(nice_title Modify the EC integration test policy param)

Go to the automatically created integration tests at
${KONFLUX_APPS_URL}/${KONFLUX_APPLICATION_NAME}/integrationtests
Edit ${KONFLUX_APPLICATION_NAME}-enterprise-contract and add a parameter as follows:
  Name: POLICY_CONFIGURATION
  Value: rhtap-releng-tenant/registry-rhtap-contract
Save changes

$(nice_title Apply pipeline customizations from main branch to the new release branch)

This should be done on top of the Konflux generated PR, (either before it's merged or after).

git checkout ${BRANCH_NAME}
hack/patch-release-pipelines.sh
hack/patch-release-pipelines.sh digest_bumps # Maybe not needed now since digests should be pretty current

Notes:
- The script tries to apply hunks one by one, but some of the hunks may be already applied
  and some of them might not apply cleanly.
- For that reason always say "no" when it offers to force apply or apply in reverse
- The manual diff review is super important since we expect this script to not get everying right
- There could be some significant changes in the new generated pipeline that aren't in main branch,
  e.g. brand new tasks, or modified task params. We should generally assume these are good changes
  and keep them, and also aim to port them back (up/down/sideways?) into main branch. If this work
  is non-trivial then file a story or stories to do that.

Review the diff between the ${KONFLUX_CLI_COMPONENT_NAME}- and cli-main-ci- pipelines
Make changes that need to be made that weren't handled by the script. The vimdiff commands
suggested below are a good way to do that. Amend the commit until you're happy with it.

Vimdiff commands:
 vimdiff +'set ft=yaml' <(git show main:.tekton/cli-main-ci-pull-request.yaml) .tekton/cli-${KONFLUX_APPLICATION_SUFFIX}-pull-request.yaml
 vimdiff +'set ft=yaml' <(git show main:.tekton/cli-main-ci-push.yaml) .tekton/cli-${KONFLUX_APPLICATION_SUFFIX}-push.yaml

EOT2

cat <<EOT3
$(nice_title Create pipeline customizations PR)

With the above commit, create a new PR if the Konflux PR was merged already, or push an
extra commit to that generated PR, for the ${BRANCH_NAME} branch. If creating a PR, be extra
careful to choose the right target branch when creating the PR e.g. it must be release-v0.4
not main, and not the konflux/references/release-v0.x branch used for PRs.

$(nice_title Create a ReleasePlan record in the tenants config repo)

The goal is to make a PR similar to https://github.com/redhat-appstudio/tenants-config/pull/286
or https://github.com/redhat-appstudio/tenants-config/pull/397 .
Consider also if you want to remove older release plans. The new release plan should look
something like this:
---
apiVersion: appstudio.redhat.com/v1alpha1
kind: ReleasePlan
metadata:
  labels:
    release.appstudio.openshift.io/auto-release: "true"
    release.appstudio.openshift.io/standing-attribution: "true"
  namespace: rhtap-contract-tenant
  name: ${KONFLUX_APPLICATION_NAME}-registry-redhat-io
spec:
  application: ${KONFLUX_APPLICATION_NAME}
  target: rhtap-releng-tenant

Note that you have to run the ./build-manifests.sh script in that repo and check in the
resulting changes.

EOT3

cat <<EOT4
$(nice_title Create a PR in the konflux-release-data repo to update the ReleasePlanAdmission record)

You need to change a few lines in the ec-cli.yaml ReleasePlanAdmission file in the konflux-release-data repo.
https://gitlab.cee.redhat.com/releng/konflux-release-data/-/merge_requests/557/diffs?commit_id=43c03446f2330f31913613fb5a0f757832780fba
should be a useful reference. Again, consider if you want to retire one of our older repo mappings.

$(nice_title Confirming it\'s working)

If the RP and the RPA PRs are both merged, any changed merged to the release branch should push out a release.
You can see releases in the releases tab:
https://console.redhat.com/preview/application-pipeline/workspaces/rhtap-contract/applications/ec-${KONFLUX_APPLICATION_SUFFIX}/releases
Viewing the release pipeline itself requires permissions in the rhtap-releng workspace.

You can confirm what images were released using the show-latest-build-versions.sh script in the hacks repo,
or by look at https://catalog.redhat.com/software/containers/rhtas/ec-rhel9/65f1f9dcfc649a18c6075de5.
or using skopeo, e.g. 'skopeo inspect docker://registry.redhat.io/rhtas/ec-rhel9:latest' or podman, e.g.
'podman run --rm registry.redhat.io/rhtas/ec-rhel9:latest version'.
EOT4
