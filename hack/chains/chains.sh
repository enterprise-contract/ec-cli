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

# Fetches the Tekton YAML descriptors for the version we depend on

set -o errexit
set -o pipefail
set -o nounset

CHAINS_VERSION="${CHAINS_VERSION:-$(cd "$(git rev-parse --show-toplevel)/tools" && go list -f '{{.Version}}' -m github.com/tektoncd/chains)}"

YAML="$(mktemp --tmpdir)"
cleanup() {
    rm -f "${YAML}"
}
trap cleanup exit

while [[ "$(curl -sSL -w '%{http_code}' -o "${YAML}" "https://storage.googleapis.com/tekton-releases/chains/previous/${CHAINS_VERSION}/release.yaml")" != "200" ]]; do
    # first fallback, remove any trailing timestamp + sha, e.g.
    # vX.Y.Z-0.TIMESTAMP-HASH -> vX.Y.Z
    if [[ "${CHAINS_VERSION}" == v*-*-* ]]; then
        CHAINS_VERSION="${CHAINS_VERSION%-*-*}"
        continue
    fi
    # second fallback, replace vX.Y.1 with vX.Y.0
    if [[ "${CHAINS_VERSION}" == *.1 ]]; then
        CHAINS_VERSION="${CHAINS_VERSION/%.1/.0}"
        continue
    fi
    # no more fallbacks, fail
    exit 1
done

cat "${YAML}"
