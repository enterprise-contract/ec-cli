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

set -o errexit
set -o nounset
set -o pipefail

# Handy for testing this script
DEFAULT_IMAGE="quay.io/redhat-user-workloads/rhtap-contract-tenant/ec-v04/cli-v04@sha256:267765750250ee46facd9adf1b6f4ec0f954a09d182070d600232582cb17d1e7"
IMAGE=${1:-"$DEFAULT_IMAGE"}

OUTPUT_DIR=./output
mkdir -p ${OUTPUT_DIR}
rm -rf ${OUTPUT_DIR}/*

MATCHER=_ARTIFACT
#MATCHER=CACHI2_ARTIFACT

ARTIFACT_PARAMS=($(
  cosign download attestation $IMAGE |
    # unpack the attestation
    jq '.payload | @base64d | fromjson' |
    # pick out the artifact task results created by the prefetch-dependencies task
    jq '.predicate.buildConfig.tasks[] | select(.name=="prefetch-dependencies").results.[] | select((. != null) and (.name | endswith("'${MATCHER}'")))' |
    # convert to $ref=$dir format
    jq -r '"\(.value)='${OUTPUT_DIR}/'\(.name)"'
))

# Fixme: I don't want to use sudo here, but if I don't I get many tar errors like:
#   ./cachi2.env: Cannot change ownership to uid 0, gid 1002380000: Invalid argument
#
# I tried tweaking --userns options, but no luck.
# Maybe removing the tar -p option would help, but I'm not sure.
#
sudo podman run --rm \
  -v ${OUTPUT_DIR}:/output:Z \
  -v ${HOME}/.docker/config.json:/home/notroot/.docker/config.json:Z \
  quay.io/redhat-appstudio/build-trusted-artifacts:latest \
  use ${ARTIFACT_PARAMS[@]}
