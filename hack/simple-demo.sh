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

# This is an image regularly built in Stonesoup for testing purposes.
# See https://github.com/hacbs-contract/golden-container
#
IMAGE=${IMAGE:-"quay.io/redhat-appstudio/ec-golden-image:latest"}


# We can use `ec validate image --image $IMAGE` but to be more
# realistic let's use the application snapshot format for the input
#
APPLICATION_SNAPSHOT="
components:
  - name: Golden Container Latest
    containerImage: ${IMAGE}
"

JSON_SNAPSHOT=$(echo "$APPLICATION_SNAPSHOT" | yq -ojson -I0)

# The key defined here should work, but if it doesn't then you can get a fresh one from the cluster:
#  - Visit https://oauth-openshift.apps.stone-prd-rh01.pg1f.p1.openshiftapps.com/oauth/token/request
#  - Authenticate and get a token, then use the oc login to authenticate
#  - kubectl get -n tekton-chains secret public-key -o json | jq -r '.data."cosign.pub" | @base64d'
#
# The key might also be available here but currently it's out of date:
#   https://raw.githubusercontent.com/redhat-appstudio/infra-deployments/main/components/pipeline-service/public/tekton-chains-signing-secret.pub
#
PUBLIC_KEY=${PUBLIC_KEY:-"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZP/0htjhVt2y0ohjgtIIgICOtQtA
naYJRuLprwIv6FDhZ5yFjYUEtsmoNcW7rx2KM6FOXGsCX3BNc7qhHELT+g==
-----END PUBLIC KEY-----"}

# Standard default sources for the EC policies
#
POLICY_SOURCE="quay.io/hacbs-contract/ec-release-policy:latest"
DATA_SOURCE="quay.io/hacbs-contract/ec-policy-data:latest"

# These should work the same if you want to use git sources
#
#POLICY_SOURCE="github.com/hacbs-contract/ec-policies//policy"
#DATA_SOURCE="github.com/hacbs-contract/ec-policies//data"

MINIMAL_CONFIG="
configuration:
  collections:
    - minimal
"

EVERYTHING_CONFIG="
configuration: {}
"

# So you can switch between the two
#
CONFIG="$MINIMAL_CONFIG"
#CONFIG="$EVERYTHING_CONFIG"

# The ECP config. Modify as required.
#
POLICY="
publicKey: |-
$(echo "$PUBLIC_KEY" | sed 's/^/  /')

sources:
  - name: EC Policies
    policy:
      - ${POLICY_SOURCE}
    data:
      - ${DATA_SOURCE}

${CONFIG}
"

JSON_POLICY=$(echo "$POLICY" | yq -ojson -I0)

# To show debug output:
#   hack/simple-demo.sh --debug
#
OPTS=${1:-}

MAIN_GO=$(git rev-parse --show-toplevel)/main.go
go run $MAIN_GO validate image --json-input "$JSON_SNAPSHOT" --policy "$(echo "$JSON_POLICY")" --info=true $OPTS | yq -P
