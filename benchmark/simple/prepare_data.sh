#!/bin/bash
# Copyright The Enterprise Contract Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Creates the files in the data directory that should contain all the data
# needed to run the benchmark, uses the ../offliner for images andplain git
# clone for the git data dependency
set -o errexit
set -o nounset
set -o pipefail

offliner="$(git rev-parse --show-toplevel)/benchmark/offliner"

dir="$(mktemp -d)"
trap 'rm -rf "${dir}"' EXIT

(
    cd "${dir}"

    imgs=(
        quay.io/konflux-ci/ec-golden-image@sha256:38a2a2e89671eece1a123f57b543612a67ad529bc66c4ad77216b7ae91ba5769
        quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles@sha256:8e6da7823756583cc48499f1c051853cbe30b2d1f127f03b6d2effbd6cd207d0
        quay.io/enterprise-contract/ec-release-policy@sha256:c7799644ff34322107919302ae0d2099a811b917a600774545d22fdcd3b49b98
    )

    for img in "${imgs[@]}"; do
        go run -C "${offliner}" . "${img}" "${dir}/data/registry/data"
    done

    git clone --no-checkout https://github.com/release-engineering/rhtap-ec-policy.git data/git/rhtap-ec-policy.git
)

tar czf data.tar.gz -C "${dir}" .