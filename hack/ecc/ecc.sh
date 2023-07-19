#!/usr/bin/env bash
# Copyright Red Hat.
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

# Fetches the EnterpriseContractPolicy CRD descriptors for the version we use

set -o errexit
set -o pipefail
set -o nounset

ROOT=$(git rev-parse --show-toplevel)

# We need the full git id and from the go.mod we get the short (12 character),
# so we clone to convert the short to the full lenght one.
# This can be overriden by specifying the ECC_VERSION environment variable
# beforehand
if [ -z "${ECC_VERSION:-}" ]; then
  SHORT_REV=$(cd "${ROOT}" && go list -f '{{slice .Version 22}}' -m github.com/enterprise-contract/enterprise-contract-controller/api)
  ECC_VERSION=$(
    TMP_ECC_GIT=$(mktemp -d)
    trap 'rm -rf "${TMP_ECC_GIT}"' EXIT
    cd "${TMP_ECC_GIT}"
    git clone -q --bare https://github.com/enterprise-contract/enterprise-contract-controller.git "${TMP_ECC_GIT}"
    git show -s --pretty=format:%H "${SHORT_REV}"
  )
fi

go run -modfile "${ROOT}/tools/go.mod" sigs.k8s.io/kustomize/kustomize/v5 build "https://github.com/enterprise-contract/enterprise-contract-controller/config/crd?ref=${ECC_VERSION}"
