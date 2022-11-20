#!/bin/env bash
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

IMAGE=${IMAGE:-"quay.io/cuipinghuo/single-container-app:9f5d549dd64aacf10e3baac90972dfd5df788324"}

PUBLIC_KEY=${PUBLIC_KEY:-"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPfwkY/ru2JRd6FSqIp7lT3gzjaEC
EAg+paWtlme2KNcostCsmIbwz+bc2aFV+AxCOpRjRpp3vYrbS5KhkmgC1Q==
-----END PUBLIC KEY-----"}

POLICY='{
  "publicKey": "'${PUBLIC_KEY//$'\n'/\\n}'",
  "sources": [
    "github.com/hacbs-contract/ec-policies//policy"
  ],
  "configuration": {
    "excludeRules": [
      "not_useful"
    ]
  }
}'

MAIN_GO=$(git rev-parse --show-toplevel)/main.go
go run $MAIN_GO validate image --image $IMAGE --policy "$POLICY" --debug | yq -P
