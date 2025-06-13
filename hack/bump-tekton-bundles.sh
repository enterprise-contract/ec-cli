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

# Updates the Pipeline definitions in .tekton to the latest versions of Task bundles

set -o errexit
set -o pipefail
set -o nounset

root_dir=$(git rev-parse --show-toplevel)

bundles="$(go run github.com/conforma/cli inspect policy-data --source oci::quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles:latest)"

for f in "${root_dir}"/.tekton/*-build.yaml; do
  # shellcheck disable=SC2016,SC2094
  cat <<< "$(yq eval-all '
    select(fileIndex == 1).trusted_tasks as $t |
    with(select(fileIndex == 0).spec.tasks[].taskRef.params[];
      with(select(.name == "bundle");
        (.value | sub("@.*", "")) as $r |
        .value |= $r + "@" + $t["oci://" + $r][0].ref
      )
    ) |
    select(fileIndex == 0)
  ' "$f" <(echo "${bundles}"))" > "$f"
done
