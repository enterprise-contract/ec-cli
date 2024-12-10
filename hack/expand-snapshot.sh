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

# This script is meant to take an existing snapshot reference which includes just
# the EC CLI image and use that to create a new snapshot which includes the EC Tekton
# bundle image.

set -o errexit
set -o nounset
set -o pipefail

# Release service includes the namespace with the resource name. Let's clean that up.
SNAPSHOT_NAME="${1#*/}"
CLI_SNAPSHOT_PATH=$2
BUNDLE_SNAPSHOT_PATH=$3

echo "Fetching ${SNAPSHOT_NAME} snapshot"
SNAPSHOT_SPEC="$(oc get snapshot ${SNAPSHOT_NAME} -o json | jq '.spec')"
echo "${SNAPSHOT_SPEC}"

echo "Verifying snapshot contains a single component"
echo "${SNAPSHOT_SPEC}" | jq -e '.components | length == 1' > /dev/null

CLI_IMAGE_REF="$(echo "${SNAPSHOT_SPEC}" | jq -r '.components[0].containerImage')"
echo "CLI image ref: ${CLI_IMAGE_REF}"

echo "Storing EC CLI snapshot in ${CLI_SNAPSHOT_PATH}"
echo "${SNAPSHOT_SPEC}" > "${CLI_SNAPSHOT_PATH}"

BUNDLE_IMAGE_REF="$(
    cosign download attestation "${CLI_IMAGE_REF}" | jq -r '.payload | @base64d | fromjson |
        .predicate.buildConfig.tasks[] | select(.name == "build-tekton-bundle") |
        .results[] | select(.name == "IMAGE_REF") | .value'
)"

echo "Bundle image ref: ${BUNDLE_IMAGE_REF}"

echo "Creating new snapshot spec for bundle and storing in ${BUNDLE_SNAPSHOT_PATH}"
echo "${SNAPSHOT_SPEC}" | jq  --arg bundle "${BUNDLE_IMAGE_REF}" \
    '.components[0].name = "tekton-bundle" | .components[0].containerImage = $bundle' | \
    tee "${BUNDLE_SNAPSHOT_PATH}"
