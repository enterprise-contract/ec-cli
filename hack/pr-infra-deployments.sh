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

# Creates a pull request with updates to the redhat-appstudio/infra-deployments
# repository. Usually run upon release.
# Usage:
#   pr-infra-deployments.sh <TASK_BUNDLE_TAG>

set -o errexit
set -o pipefail
set -o nounset

TASK_BUNDLE_TAG="$1"
TASK_BUNDLE_DIGEST="$(skopeo inspect "docker://quay.io/hacbs-contract/ec-task-bundle:${TASK_BUNDLE_TAG}" | jq -r .Digest)"
TASK_BUNDLE_REF="quay.io/hacbs-contract/ec-task-bundle:${TASK_BUNDLE_TAG}@${TASK_BUNDLE_DIGEST}"

# setup
WORKDIR=$(mktemp -d)
trap 'rm -rf "${WORKDIR}"' EXIT
cd "${WORKDIR}" || exit 1

gh repo clone hacbs-contract/infra-deployments
cd infra-deployments || exit 1
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  git remote set-url origin git@github.com:hacbs-contract/infra-deployments.git
  git config --global user.email "${GITHUB_ACTOR}@users.noreply.github.com"
  git config --global user.name "${GITHUB_ACTOR}"
  mkdir -p "${HOME}/.ssh"
  echo "${DEPLOY_KEY}" > "${HOME}/.ssh/id_ed25519"
  chmod 600 "${HOME}/.ssh/id_ed25519"
  trap 'rm -rf "${WORKDIR}" "${HOME}/.ssh/id_rsa"' EXIT
  export GITHUB_USER="$GITHUB_ACTOR"
fi
git checkout -b ec-update --track upstream/main

# replacements
yq e -i '.configMapGenerator[] |= select(.name == "ec-defaults").literals[] |= select(. == "verify_ec_task_bundle=*") = "verify_ec_task_bundle='"${TASK_BUNDLE_REF}"'"' components/enterprise-contract/kustomization.yaml

# commit & push
git commit -a -m "enterprise contract update"
git push --force -u origin ec-update

# create pull request, don't fail if it already exists
gh pr create --fill --no-maintainer-edit --repo redhat-appstudio/infra-deployments || true
