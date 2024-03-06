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

# If the arg is set to digest_bumps then add only the digest bumps
digest_bumps=${1:-""}

# Sanity check I guess
if [[ ! "$current_branch" =~ ^release- ]]; then
  echo "Expecting to be in a release branch!"
  exit 1
fi

# The release name is the branch name with release- trimmed off the front
release_name=${current_branch#"release-"}

# Will append to this and echo it later
diff_help=""

# One each for the two pipelines created by Konflux
for p in pull-request push; do
  main_pipeline=".tekton/cli-main-ci-$p.yaml"
  release_pipeline=".tekton/cli-${release_name/./}-$p.yaml"

  if [[ "$digest_bumps" != "digest_bumps" ]]; then
    # Find all significant changes.
    # Use grep to exclude digest bumps and initial creation.
    changes=$( git log main --reverse --pretty=%h --no-merges --invert-grep --regexp-ignore-case \
      --grep="Update RHTAP references" \
      --grep="Update Konflux references" \
      --grep="Konflux CI update" \
      --grep="Konflux update" \
      --grep="Red Hat Trusted App Pipeline update" \
      -- $main_pipeline )
  else
    # Find only the digest bumps
    changes=$( git log main --reverse --pretty=%h --regexp-ignore-case \
      --grep="Update RHTAP references" \
      --grep="Update Konflux references" \
      -- $main_pipeline )
  fi

  # Loop over each commit
  for sha in $changes; do
    git show $sha $main_pipeline

    echo ""
    echo "Applying the above changes to '$release_pipeline'"
    read -p "Press any key to continue..."
    echo ""

    # Create a diff file and apply the patch
    # (Can't use git apply since it is a different file)
    # If the patch doesn't apply, keep going anyhow
    git diff $sha^ $sha $main_pipeline | patch -p1 $release_pipeline || true

    # Stage the changes
    git add $release_pipeline

    echo ""
  done

  # Let's clean up by removing the main branch pipeline from the release branch
  git rm $main_pipeline

  # Prepare handy commands for comparing the patched pipeline to the corresponding main branch pipeline
  diff_help=$(echo "$diff_help"; echo "  vimdiff <(git show main:$main_pipeline) $release_pipeline")
done

echo ""
echo "Patching done. Ready to make a commit."
read -p "Press any key to continue..."
echo ""

# Make the commit
git commit -m "chore: Modify default pipelines for $release_name" \
  -m "Apply changes to the Konflux generated default pipelines." \
  -m "Also remove the main branch pipelines since they're not needed in the release branch." \
  -m "(Commit created with hack/patch-release-pipelines.sh $digest_bumps)"

# Invite the human to look at it
echo ""
echo "Please review the commit and see if you like it."
echo "Please also review the diff between the cli-main-ci pipelines and the corresponding release pipelines."
echo "(You can use the following vimdiff commands to see what the differences are.)"
echo "$diff_help"
