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

IMAGE=${IMAGE:-"quay.io/redhat-appstudio/ec-golden-image:latest"}

#ec-golden-image is signed with staging public key, to verify, use the below public key
#(https://raw.githubusercontent.com/redhat-appstudio/infra-deployments/main/components/pipeline-service/public/tekton-chains-signing-secret.pub)
PUBLIC_KEY=${PUBLIC_KEY:-"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEODgxyIz09vBqJlXXzjp/X2h17WIt
jCVQhnDYVWHvXhw6rgqGeg6NTUxIEhRQqQZaF9mcBotHkuYGJfYZbai+FA==
-----END PUBLIC KEY-----"}

POLICY_SOURCE="quay.io/hacbs-contract/ec-release-policy:latest"
DATA_SOURCE="quay.io/hacbs-contract/ec-policy-data:latest"

#POLICY_SOURCE="github.com/hacbs-contract/ec-policies//policy"
#DATA_SOURCE="github.com/hacbs-contract/ec-policies//data"

POLICY='{
  "publicKey": "'${PUBLIC_KEY//$'\n'/\\n}'",
  "sources": [
    {
      "name": "EC Policies",
      "policy": [
        "'${POLICY_SOURCE}'"
      ],
      "data": [
        "'${DATA_SOURCE}'"
      ]
    }
  ],
  "configuration": {
    "exclude": [
    ],
    "include": [
      "*"
    ]
  }
}'

# To show debug output:
#   hack/simple-demo.sh --debug
OPTS=${1:-}

MAIN_GO=$(git rev-parse --show-toplevel)/main.go
go run $MAIN_GO validate image --image $IMAGE --policy "$POLICY" $OPTS | yq -P
