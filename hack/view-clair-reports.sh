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
DEFAULT_IMAGE="quay.io/redhat-user-workloads/rhtap-contract-tenant/ec-v05/cli-v05@sha256:56513fe272f69e7ba06e23515e8add401f410febc5ae60b372416fde95255211"

IMAGE=${1:-"$DEFAULT_IMAGE"}

OPT=${2:-""}

REPO=$(echo "$IMAGE" | cut -d '@' -f 1)

CLAIR_REPORT_SHAS=$(
  cosign download attestation $IMAGE | jq -r '.payload|@base64d|fromjson|.predicate.buildConfig.tasks[]|select(.name=="clair-scan").results[]|select(.name=="REPORTS").value|fromjson|.[]'
)

# For multi-arch the same report maybe associated with each of the per-arch
# images. Use sort uniq to avoid displaying it multiple times, but still
# support the possibility of different reports
ALL_BLOBS=""

for sha in $CLAIR_REPORT_SHAS; do
  blob=$(skopeo inspect --raw docker://$REPO@$sha | jq -r '.layers[].digest')
  ALL_BLOBS=$((echo $ALL_BLOBS; echo $blob) | sort | uniq)
done

for b in $ALL_BLOBS; do
  echo "---"
  echo "#"
  echo "# $REPO@$b"

  # For a readable list of CVEs
  YQ_QUERY='.vulnerabilities | to_entries[].value | .package_name = .package.name | pick(["name", "description", "issued", "normalized_severity", "package_name", "fixed_in_version"]) | [.]'

  if [ "$OPT" == "--raw" ]; then
    # Output everything
    YQ_QUERY='.'
  fi

  if [ "$OPT" == "--high" ]; then
    echo "# Severity High"
    YQ_QUERY="$YQ_QUERY | .[] |select(.normalized_severity == \"High\") | [.]"
  fi

  if [ "$OPT" == "--critical" ]; then
    echo "# Severity Critical"
    YQ_QUERY="$YQ_QUERY | .[] |select(.normalized_severity == \"Critical\") | [.]"
  fi

  echo "#"
  oras blob fetch "$REPO@$b" --output - | yq -P "$YQ_QUERY"
done
