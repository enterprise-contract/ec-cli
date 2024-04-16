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

# Assumptions:
# 1. The file VERSION exists and contains the major.minor version number
# 2. The most recent commit that changed that file is the commit that
#    bumped the minor version number.
# 3. The only way that a change arrives in main branch is via a merge
#    commit, i.e. no direct pushes to main.
# 4. Git checkouts are done with fetch-depth=0 so we have enough history
#    to see when the VERSION file changed.

# The VERSION file in the top level directory
VERSION_FILE=$(git rev-parse --show-toplevel)/VERSION

# Read its contents
MAJOR_MINOR=$(cat ${VERSION_FILE})

# Most recent sha where $VERSION_FILE was modified.
# Using a tag for this would be reasonable, but I'm trying to
# avoid having non-useful (from a user's point of view) tags
# cluttering up our tag list.
VERSION_BUMP_SHA=$(git log -n1 --format=%H -- ${VERSION_FILE})

# How many merge commits happened since the most recent minor version bump
MERGES_SINCE_VERSION_BUMP=$(git rev-list --merges --count ${VERSION_BUMP_SHA}..HEAD)

# Count the parent shas of the current commit.
# Used to detect if we're at a merge commit.
PARENT_SHA_COUNT=$(git log -n1 --format=%P | wc -w)

# Subtract 1 because we want the first build in main branch after the
# version bump to be X.Y.0
PATCH_NUM=$((${MERGES_SINCE_VERSION_BUMP} - 1))

# Handle edge case where $VERSION_FILE was modified in the current PR
[ $PATCH_NUM -lt 0 ] && PATCH_NUM=0

if [ ${PARENT_SHA_COUNT} -lt 2 ]; then
  # Must be a local build or a CI build in an unmerged PR.
  # Use something like v0.3.0-ci-eecf77f9
  SHORT_SHA=$(git rev-parse --short=8 HEAD)
  FULL_VERSION="v${MAJOR_MINOR}.${PATCH_NUM}-ci-${SHORT_SHA}"
else
  # Must be building on a merge commit
  # Use a short and tidy version, e.g. v0.3.0
  FULL_VERSION="v${MAJOR_MINOR}.${PATCH_NUM}"
fi

echo ${FULL_VERSION}
