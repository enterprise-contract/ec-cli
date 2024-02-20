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

RELEASE_NAME=${1:-""}
if [[ $RELEASE_NAME == "" ]]; then
  echo "Please provide a release name, e.g. v0.1-tech-preview, or v1.1"
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

# Explain what needs to be done next
# (We could make this more automated in future.)
cat <<EOT

Next steps:

# Create the new release branch in the upstream repo
git fetch upstream
git push upstream refs/remotes/upstream/main:refs/heads/${BRANCH_NAME}

# Make your local version of the release branch
git checkout -b ${BRANCH_NAME} upstream/${BRANCH_NAME}

# Create the new application in Konflux
Login at ${KONFLUX_APPS_URL}
Create a new application by importing code from https://github.com/enterprise-contract/ec-cli
Set Git reference to ${BRANCH_NAME} and click "Import code"
Set the application name to ${KONFLUX_APPLICATION_NAME}
Set the component name to ${KONFLUX_CLI_COMPONENT_NAME}
Set Dockerfile to Dockerfile.dist
Unset the "Default build pipeline" toggle
Click "Create application"

# Wait for PR
Wait for the PR to be created
Go look at the PR in GitHub
Wait for the PR to pass the ${KONFLUX_CLI_COMPONENT_NAME}-on-pull-request check
You can also watch the activity at ${KONFLUX_APPS_URL}/${KONFLUX_APPLICATION_NAME}/activity/pipelineruns
When it's done you can merge. (Continue to next section while you're waiting...)

# Modify EC policy config
Go to the integration tests at ${KONFLUX_APPS_URL}/${KONFLUX_APPLICATION_NAME}/integrationtests
Edit ${KONFLUX_APPLICATION_NAME}-enterprise-contract and add a parameter as follows:
  Name: POLICY_CONFIGURATION
  Value: github.com/enterprise-contract/config//redhat-no-hermetic
Save changes

# Apply pipeline modifications
git checkout ${BRANCH_NAME}
hack/patch-release-pipelines.sh
hack/patch-release-pipelines.sh digest_bumps # maybe
Review the diff between the ${KONFLUX_CLI_COMPONENT_NAME}- and cli-main-ci- pipelines
Review the generated commit and then create a PR for the ${BRANCH_NAME} branch with that commit
(Todo maybe: If you want, try adding this commit to the PR created by Konflux before merging that PR.)

EOT

# Todo: What about the RPA?
