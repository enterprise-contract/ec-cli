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

GIT_ROOT=$(git rev-parse --show-toplevel)
EC=${EC:-"${GIT_ROOT}/dist/ec"}
LOCAL_DIR=${GIT_ROOT}/hack/builtin-experiments
DATA_DIR=${LOCAL_DIR}/data/data
POLICY_DIR=${LOCAL_DIR}/policy/policy

mkdir -p ${DATA_DIR} ${POLICY_DIR}

# This has no attestation currently...
#IMAGE=${IMAGE:-"quay.io/redhat-appstudio/ec-golden-image:latest"}

# This is the ec build for TAS so it should be good 🐕🥣
IMAGE=${IMAGE:-"quay.io/redhat-user-workloads/rhtap-contract-tenant/ec-v02/cli-v02:c862b0f77bb10082d1440e0d4b6a4e9645b83382"}

# The image digest must be specified explictly so go look it up
IMAGE_DIGEST=$(skopeo inspect --no-tags docker://$IMAGE | jq -r .Digest)
FULL_IMAGE_REF="$IMAGE@$IMAGE_DIGEST"

# Input looks like this
INPUT_JSON='{
  "image": {
    "ref": "'$FULL_IMAGE_REF'"
  }
}'

# A minimal ECP using local files
# ec looks for specific subdirs under the source's root location
# so that's why we have policy/policy and data/data
POLICY_JSON='{
  "sources": [
    {
      "policy": [
        "'$LOCAL_DIR'/policy"
      ],
      "data": [
        "'$LOCAL_DIR'/data"
      ]
    }
  ]
}'

# Public key for the signature of the image we're verifying
PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZP/0htjhVt2y0ohjgtIIgICOtQtA
naYJRuLprwIv6FDhZ5yFjYUEtsmoNcW7rx2KM6FOXGsCX3BNc7qhHELT+g==
-----END PUBLIC KEY-----"

# Hack hack...
echo '{
  "sigstore_opts": {
    "ignore_rekor": true,
    "public_key": "'${PUBLIC_KEY//$'\n'/\\n}'"
  }
}' > ${DATA_DIR}/sigstore_opts.json

# The acceptance test rego is pretty much prod-ready.. :)
# Tweak one line to make it work with the sigstore_opts data we just created above
sed \
  's/^_sigstore_opts :=.*/_sigstore_opts := object.union(data.config.default_sigstore_opts, data.sigstore_opts)/' \
  ${GIT_ROOT}/acceptance/examples/sigstore.rego \
  > ${POLICY_DIR}/sigstore.rego

echo -e "\n* Input:\n"
echo "$INPUT_JSON" | yq -P

echo -e "\n* EC results:\n"
$EC validate input \
  --file <(echo $INPUT_JSON) \
  --policy "$(echo $POLICY_JSON)" \
  --show-successes \
  --info \
  | yq -P
