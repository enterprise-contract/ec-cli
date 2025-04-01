#!/usr/bin/env bash
# Copyright The Conforma Contributors
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

SNAPSHOT_SPEC=$1
TARGET_REPO=$2

echo "Target repo: ${TARGET_REPO}"

echo "Verifying snapshot contains a single component"
echo "${SNAPSHOT_SPEC}" | jq -e '.components | length == 1' > /dev/null

GIT_SHA="$(echo "${SNAPSHOT_SPEC}" | jq -r '.components[0].source.git.revision')"
IMAGE_REF="$(echo "${SNAPSHOT_SPEC}" | jq -r '.components[0].containerImage')"

TAGS=(
    'latest'
    "${GIT_SHA}"
)
for tag in "${TAGS[@]}"; do
    echo "Pushing image with tag ${tag}"
    cosign copy --force "${IMAGE_REF}" "${TARGET_REPO}:${tag}"
done
