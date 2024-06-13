#!/usr/bin/bash
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

BUILDS="${1}"

# Generally blank, but will be set to "redhat" for Konflux builds
BUILD_SUFFIX="${2:-""}"

EC_FULL_VERSION=$(hack/derive-version.sh "${BUILD_SUFFIX}")

echo "EC_FULL_VERSION=$EC_FULL_VERSION"
echo "BUILDS=$BUILDS"

for os_arch in ${BUILDS}; do
    GOOS="${os_arch%_*}"
    GOARCH="${os_arch#*_}"
    [[ "$GOOS" == "windows" ]] && DOT_EXE=".exe" || DOT_EXE=""
    BINFILE="ec_${GOOS}_${GOARCH}${DOT_EXE}"
    echo "Building ${BINFILE} for ${EC_FULL_VERSION}"
    GOOS="${GOOS}" GOARCH="${GOARCH}" go build \
        -trimpath \
        --mod=readonly \
        -ldflags="-s -w -X github.com/enterprise-contract/ec-cli/internal/version.Version=${EC_FULL_VERSION}" \
        -o "dist/${BINFILE}"; \
    sha256sum -b dist/${BINFILE} > dist/${BINFILE}.sha256; \
done
