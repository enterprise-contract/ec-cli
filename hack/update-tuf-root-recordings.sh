#!/usr/bin/env bash
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

# Some acceptance tests rely on interactions with the TUF mirror. This script is responsible for
# recording such interactions so the acceptance tests can be executed in an "offline" manner.
# However, such recorded data expires, ~ 6 months. At that point, re-running this script should
# be enough to regenerate the recordings. Upon success, there should be various recoding files
# modified. Be sure to commit those.
#
# Usage:
#   ./hack/generate-test-signed-images.sh

set -euo pipefail
TUF_MIRROR="${TUF_MIRROR:-https://tuf-repo-cdn.sigstage.dev}"
TUF_ROOT_URL="${TUF_ROOT_URL-https://raw.githubusercontent.com/sigstore/root-signing-staging/main/metadata/root.json}"

recordings="${PWD}/acceptance/wiremock/recordings/tuf"
rm -rf "${recordings}"

function cleanup() {
    docker rm -f wiremock.local || true
}
trap cleanup EXIT

docker run -d --rm --network=host -e uid="$(id -u)" \
    --name wiremock.local \
    -v "${recordings}:/home/wiremock:Z" \
    wiremock/wiremock:2.33.2 \
    --proxy-all="${TUF_MIRROR}" \
    --record-mappings \
    --verbose

# Wait a bit to make sure wiremock has a chance to come up
sleep 2

export TUF_ROOT="$(mktemp -d)"
cosign initialize \
    --mirror http://localhost:8080 \
    --root <(curl -L ${TUF_ROOT_URL})
