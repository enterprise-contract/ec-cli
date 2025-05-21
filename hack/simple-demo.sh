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

# This is an image regularly built in Konflux for testing purposes.
# See https://github.com/conforma/golden-container
IMAGE=${IMAGE:-"quay.io/konflux-ci/ec-golden-image:latest"}

# Assume the latest image was pushed already
GIT_REPO=${GIT_REPO:-conforma/golden-container}
GIT_SHA=${GIT_SHA:-$(curl -s "https://api.github.com/repos/${GIT_REPO}/commits?per_page=1" | jq -r '.[0].sha')}

# We can use `ec validate image --image $IMAGE` but to be more
# realistic let's use the application snapshot format for the input.
# Also, this allows us to add the "source" key which is needed for
# the `slsa_source_correlated` checks to pass
APPLICATION_SNAPSHOT='{
  "components": [
    {
      "name": "golden-container",
      "containerImage": "'${IMAGE}'",
      "source": {
        "git": {
          "url": "https://github.com/'${GIT_REPO}'",
          "revision": "'${GIT_SHA}'"
        }
      }
    }
  ]
}'

# The key defined here should work, but if it doesn't then you can get a fresh one from the cluster:
# - Visit https://oauth-openshift.apps.stone-prd-rh01.pg1f.p1.openshiftapps.com/oauth/token/request
# - Authenticate and get a token, then use the oc login to authenticate
# - kubectl get -n openshift-pipelines secret public-key -o json | jq -r '.data."cosign.pub" | @base64d'
KONFLUX_PROD_KEY="-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZP/0htjhVt2y0ohjgtIIgICOtQtA
naYJRuLprwIv6FDhZ5yFjYUEtsmoNcW7rx2KM6FOXGsCX3BNc7qhHELT+g==
-----END PUBLIC KEY-----"

KONFLUX_STAGE_KEY="-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExIJfBe0aQb8jiQo1roYAi+YlAxr5
thSeH7kghWZnAzFeZOUsqMy13LiLGuVRuLkbGNktaToBeT7DyXiC+aIntw==
-----END PUBLIC KEY-----"

PUBLIC_KEY=${PUBLIC_KEY:-$KONFLUX_PROD_KEY}
#PUBLIC_KEY=${PUBLIC_KEY:-$KONFLUX_STAGE_KEY}

# Adjust as required
POLICY_YAML=${POLICY_YAML:-"github.com/enterprise-contract/config//default"}
#POLICY_YAML=${POLICY_YAML:-"github.com/enterprise-contract/config//redhat-no-hermetic"}
#POLICY_YAML=${POLICY_YAML:-"./policy.yaml"}

OUTPUT=${OUTPUT:-text}
#OUTPUT=${OUTPUT:-yaml}

MAIN_GO=$(git rev-parse --show-toplevel)/main.go

# Use `EC=ec` to avoid recompiling
EC=${EC:-"go run $MAIN_GO"}

# Additional parameters will be included, e.g.:
#   hack/simple-demo.sh --output appstudio=appstudio.json --debug
$EC validate image \
  --json-input "${APPLICATION_SNAPSHOT}" \
  --policy "${POLICY_YAML}" \
  --public-key <(echo "${PUBLIC_KEY}") \
  --ignore-rekor \
  --show-successes \
  --info \
  --output ${OUTPUT} \
  "$@"
