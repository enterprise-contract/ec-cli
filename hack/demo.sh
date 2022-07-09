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


set -o errexit
set -o nounset
set -o pipefail
set -o posix

HACK_DIR="$(dirname "${BASH_SOURCE[0]}")"
EC="${HACK_DIR}/../dist/ec_$(go env GOOS)_$(go env GOARCH)"
SNAPSHOT="$(cat ${HACK_DIR}/application_snapshot.json)"

# To run with debug output enabled:
#  EC_DEBUG=1 hack/demo.sh
[[ -n "${EC_DEBUG:-}" ]] && DEBUG_OPT="--debug"

echo "Using ec version $("${EC}" version)"

if [[ ! -x "${EC}" ]]; then
  (cd "${HACK_DIR}/.."; make)
fi

kubectl create namespace demo --dry-run=client -o yaml |kubectl apply -f -

kubectl create -o yaml --dry-run=client -f - <<EOF | kubectl apply -f -
apiVersion: appstudio.redhat.com/v1alpha1
kind: EnterpriseContractPolicy
metadata:
  namespace: demo
  name: ec-demo
spec:
  description: Demo Enterprise Contract policy configuration
  exceptions:
    nonBlocking:
    - not_useful
    - test:conftest-clair
  sources:
  - git:
      repository: https://github.com/simonbaird/ec-policies/policy
      revision: main
EOF

for IMG in 'quay.io/hacbs-contract-demo/single-nodejs-app:120e9a3' 'quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f' 'quay.io/hacbs-contract-demo/single-container-app:62c06bf'; do
  printf "\n\n🩺 Evaluating policy for %s\n\n" "${IMG}"
  echo "💲 ${EC}" validate image --image "${IMG}" --public-key "${HACK_DIR}/cosign.pub" --policy demo/ec-demo ${DEBUG_OPT:-}
  "${EC}" validate image --image "${IMG}" --public-key "${HACK_DIR}/cosign.pub" --policy demo/ec-demo ${DEBUG_OPT:-} | jq
done

printf "\n\n🩺 Evaluating application snapshot:\n%s\n\n" "${SNAPSHOT}"
echo "💲 ${EC}" validate image --file-path "${HACK_DIR}/application_snapshot.json" --public-key "${HACK_DIR}/cosign.pub" --policy demo/ec-demo ${DEBUG_OPT:-}
"${EC}" validate image --file-path "${HACK_DIR}/application_snapshot.json" --public-key "${HACK_DIR}/cosign.pub" --policy demo/ec-demo ${DEBUG_OPT:-} | jq
