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

# Notes:
# Derive the version from the branch name with the "release-" prefix removed
# if it's present, e.g. in the branch "release-v0.1-alpha" the version will
# be "v0.1-alpha"
#
# If the branch doesn't start with release- then assume it's not a release
# branch and build just a single binary to save time and cpu cycles. If the
# branch is a release branch then build all the binaries in ${BUILD_LIST}.
#
# The normal way to get the branch name is this:
#   EC_GIT_BRANCH=$( git rev-parse --abbrev-ref HEAD )
# but it doesn't work because the git-clone task checks out a sha directly
# rather than a branch. That's why we need to use `git for-each-ref`. Beware
# that testing this locally requires that you push the relevant branches to
# your 'origin' remote.
#
# Note that EC_GIT_ORIGIN_BRANCH, EC_GIT_BRANCH may be blank in a pre-merge PR
# because the PR branch refs are generally not present. In that case we'll use
# "_ci_build" as the version.
#
# For the EC_PATCH_NUM we assume there is a v0.2.0 (for example) tag created
# by a human. Using --merges there because we assume every build happens after
# a PR is merged.
#

BUILD_LIST="${1:-darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 linux_ppc64le linux_s390x windows_amd64}"
TARGETOS=$2
TARGETARCH=$3

EC_GIT_ORIGIN_BRANCH=$( git for-each-ref --points-at HEAD --format='%(refname:short)' refs/remotes/origin/ )
echo "EC_GIT_ORIGIN_BRANCH=$EC_GIT_ORIGIN_BRANCH"

EC_GIT_BRANCH=${EC_GIT_ORIGIN_BRANCH#"origin/"}
echo "EC_GIT_BRANCH=$EC_GIT_BRANCH"

EC_VERSION=${EC_GIT_BRANCH#"release-"}
if [[ "${EC_GIT_BRANCH}" != release-* ]]; then
    EC_VERSION=v0.3
    EC_PATCH_NUM=$(git rev-list --count HEAD)-$(git rev-parse --short HEAD)
    BUILDS="${TARGETOS}_${TARGETARCH}"
else
    EC_BASE_TAG="${EC_VERSION}.0"
    echo "EC_BASE_TAG=$EC_BASE_TAG"
    git log -n1 --format="%h %s" "$EC_BASE_TAG"

    EC_PATCH_NUM=$( git rev-list --merges --count ${EC_BASE_TAG}..HEAD )
    BUILDS="${BUILD_LIST}"
fi

EC_FULL_VERSION="${EC_VERSION}.${EC_PATCH_NUM}"

echo "EC_VERSION=$EC_VERSION"
echo "EC_PATCH_NUM=$EC_PATCH_NUM"
echo "EC_FULL_VERSION=$EC_FULL_VERSION"
echo "BUILDS=$BUILDS"

for os_arch in ${BUILDS}; do
    export GOOS="${os_arch%_*}"
    export GOARCH="${os_arch#*_}"
    [[ "$GOOS" == "windows" ]] && DOT_EXE=".exe" || DOT_EXE=""
    BINFILE="ec_${GOOS}_${GOARCH}${DOT_EXE}"
    echo "Building ${BINFILE} for ${EC_FULL_VERSION}"
    go build \
        -trimpath \
        --mod=readonly \
        -ldflags="-s -w -X github.com/enterprise-contract/ec-cli/internal/version.Version=${EC_FULL_VERSION}" \
        -o "dist/${BINFILE}"; \
    sha256sum -b dist/${BINFILE} > dist/${BINFILE}.sha256; \
done
