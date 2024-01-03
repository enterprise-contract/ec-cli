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

current_branch=$(git rev-parse --abbrev-ref HEAD)

# Sanity check I guess
if [[ ! "$current_branch" =~ ^release- ]]; then
  echo "Expecting to be in a release branch!"
  exit 1
fi

# The release name is the branch name with release- trimmed off the front
release_name=${current_branch#"release-"}

# One each for the two pipelines created by RHTAP
for p in pull-request push; do
  main_pipeline=".tekton/cli-main-ci-$p.yaml"
  release_pipeline=".tekton/cli-${release_name/./}-$p.yaml"

  # Find all significant changes.
  # Use grep to exclude digest bumps and initial creation.
  changes=$( git log main --reverse --pretty=%h --invert-grep \
    --grep="Update RHTAP references" --grep="Red Hat Trusted App Pipeline update" \
    -- $main_pipeline )

  # Loop over each commit
  for sha in $changes; do
    echo "Applying changes from commit $(git log -n1 --pretty="'%h %s'" $sha)"\
      "to pipeline definition file '$release_pipeline'"

    # Create a diff file and apply the patch
    # (Can't use git apply since it is a different file)
    git diff $sha^ $sha $main_pipeline | patch -p1 $release_pipeline

    # Stage the changes
    git add $release_pipeline
  done

  # Tidy up by removing the main branch pipeline
  git rm $main_pipeline
done

# Make the commit
git commit -m "chore: Modify default pipelines for $release_name" \
  -m "Apply changes to the RHTAP generated default pipelines." \
  -m "Also remove the main branch pipelines." \
  -m "(Commit created with hack/patch-release-pipelines.sh)"

# Invite the human to look at it
echo "Please review the commit and see if you like it."
