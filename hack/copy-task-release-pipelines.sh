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

# The release name is the branch name with release- trimmed off the front, e.g. v0.2
release_name=${current_branch#"release-"}

# With dots removed, e.g. v02
short_release_name=${release_name/./}

# Will append to this and echo it later
diff_help=""

# One each for the two pipelines created by Konflux
for p in pull-request push; do
  main_pipeline=".tekton/verify-enterprise-contract-task-main-ci-$p.yaml"
  release_pipeline=".tekton/verify-enterprise-contract-task-$short_release_name-$p.yaml"

  # Beware: If the branch name is long enough there'll be a newline after
  # "target_branch ==" and the second sed command won't work
  cat $main_pipeline \
    | sed "s/main-ci/$short_release_name/g" \
    | sed "s/target_branch == \"main\"/target_branch == \"$current_branch\"/" \
    > $release_pipeline

  git add $release_pipeline

  # Let's clean up by removing the main branch pipeline from the release branch
  git rm $main_pipeline

  # Prepare handy commands for comparing the patched pipeline to the corresponding main branch pipeline
  diff_help=$(echo "$diff_help"; echo "  vimdiff +'set ft=yaml' <(git show main:$main_pipeline) $release_pipeline")
done

git commit -m "chore: Copy task bundle pipelines for $release_name" \
  -m "Copy the pipeline definitions from the main branch versions and apply name changes." \
  -m "Also remove the main branch pipelines since they're not needed in the release branch." \
  -m "(Commit created with hack/copy-task-release-pipelines.sh)"

echo "To compare the copied pipelines with the main branch pipelines:"
echo "$diff_help"
