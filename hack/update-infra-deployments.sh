#!/usr/bin/env bash
# Copyright 2022 Red Hat, Inc.
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

# Updates a local clone of redhat-appstudio/infra-deployments to use the latest
# packages produced by this repository.
# Usage:
#   update-infra-deployments.sh <PATH_TO_INFRA_DEPLOYMENTS> [<TAG>]

set -o errexit
set -o pipefail
set -o nounset

TARGET_DIR="${1}"
cd "${TARGET_DIR}" || exit 1

echo 'Resolving task bundle...'
TASK_BUNDLE_TAG="${2:-snapshot}"
MANIFEST=$(mktemp --tmpdir)
function cleanup() {
    rm "${MANIFEST}"
}
trap cleanup EXIT
skopeo inspect "docker://quay.io/hacbs-contract/ec-task-bundle:${TASK_BUNDLE_TAG}" --raw > "${MANIFEST}"
TASK_BUNDLE_DIGEST="$(skopeo manifest-digest "${MANIFEST}")"
REVISION="$(jq -r '.annotations["org.opencontainers.image.revision"]' "${MANIFEST}")"
if [[ -n "${REVISION}" && "${REVISION}" != null ]]; then
    TASK_BUNDLE_TAG="${REVISION}"
fi
TASK_BUNDLE_REF="quay.io/hacbs-contract/ec-task-bundle:${TASK_BUNDLE_TAG}@${TASK_BUNDLE_DIGEST}"
echo "Resolved bundle is ${TASK_BUNDLE_REF}"

echo 'Updating infra-deployments...'
REF="${TASK_BUNDLE_REF}" yq e -i \
    '.configMapGenerator[] |=
        select(.name == "ec-defaults").literals[] |=
            select(. == "verify_ec_task_bundle=*") = "verify_ec_task_bundle=" + env(REF)' \
    components/enterprise-contract/kustomization.yaml

echo 'infra-deployments updated successfully'
