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

# Runs `cosign sign-blob` in cluster and `cosign verify-blob` locally, the
# cluster needs to be setup with hack/setup-dev-environment.sh

set -o errexit
set -o pipefail
set -o nounset
set -o errtrace
# Enable debugging
#set -o xtrace

if (( $# != 1 )); then
    echo "usage $0 <file to sign>"
    exit 1
fi

export TUF_ROOT="$(mktemp --directory --tmpdir)"

SERVICE_ACCOUNT="${2:-default}"

LOGS="$(mktemp --tmpdir)"
SIGNATURE="$(mktemp --tmpdir)"
CERTIFICATE="$(mktemp --tmpdir)"
TLOG_ENTRY="$(mktemp --tmpdir)"
cleanup() {
    [ -o xtrace ] && echo -e "📜 \033[1mCosign logs\033[0m" && cat "${LOGS}"

    rm -rf "${LOGS}" "${SIGNATURE}" "${CERTIFICATE}" "${TLOG_ENTRY}" "${TUF_ROOT}"
}
trap cleanup exit

cosign initialize --mirror http://tuf.localhost --root http://tuf.localhost/root.json

ls -l "${TUF_ROOT}"

cosign sign-blob \
    --oidc-issuer https://kubernetes.default.svc.cluster.local \
    --fulcio-url http://fulcio.localhost \
    --identity-token <(kubectl create token "${SERVICE_ACCOUNT}") \
    --rekor-url http://rekor.localhost \
    --output-file "${SIGNATURE}" \
    --yes \
    "$1" \
    2> "${LOGS}"

echo -e "🎗️ \033[1mCertificate\033[0m"
sed -n "/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p" "${LOGS}" > "${CERTIFICATE}"
cat "${CERTIFICATE}"

echo -e "📝 \033[1mSignature\033[0m"
cat "${SIGNATURE}"

echo -e "🪵 \033[1mSignature tlog entry\033[0m"
rekor-cli get --rekor_server http://rekor.localhost --log-index "$(sed -r -n -e 's/tlog entry created with index: ([0-9]+)/\1/p' "${LOGS}")" > "${TLOG_ENTRY}"
cat "${TLOG_ENTRY}"

echo -e "🔍 \033[1mVerifying signature\033[0m"
cosign verify-blob \
    --certificate "${CERTIFICATE}" \
    --certificate-chain <(kubectl -n fulcio-system get secret fulcio-server-secret -o jsonpath='{.data.cert}'|base64 -d) \
    --certificate-identity-regexp '.*' \
    --certificate-oidc-issuer https://kubernetes.default.svc.cluster.local \
    --rekor-url http://rekor.localhost \
    --signature "${SIGNATURE}" \
    "$1"
