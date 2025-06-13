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

set -o errexit
set -o nounset
set -o pipefail
set -o posix

mkdir -p stats
# shellcheck disable=SC2016
{
    curl --silent --fail https://conforma.dev/cli/stats.json || echo -n ''
    gh api graphql --field query='{
    repository(owner: "conforma", name: "cli") {
        release(tagName: "snapshot") {
        createdAt
        releaseAssets(first: 50) {
            nodes {
            name
            downloadCount
            }
        }
        }
    }
    }' --jq '.data.repository.release as $r |
    {
    "created": $r.createdAt,
    "updated" : now | todate,
    "data": [
        $r.releaseAssets.nodes[] as $n |
        $n.name | ltrimstr("ec_") | split("[_.]"; "") as $parts |
        $n | {
        "os": $parts[0],
        "architecture": $parts[1],
        "hash": ($parts[2] != null),
        "downloads": .downloadCount
        }
    ]
    }' || true
} > stats/stats.json
