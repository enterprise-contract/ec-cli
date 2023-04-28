#!/usr/bin/env bash
# Copyright 2023 Red Hat, Inc.
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
# set -o xtrace

if (( $# != 1 )); then
    echo "usage $0 <file to sign>"
    exit 1
fi

# Setup for the Cosign image from Sigstore
IMAGE=gcr.io/projectsigstore/cosign
SIGSTORE_CONF=/home/nonroot/.sigstore

# For custom container this might look like
# IMAGE=quay.io/zregvart_redhat/cosign-debug
# SIGSTORE_CONF=/root/.sigstore

LOGS="$(mktemp --tmpdir)"
SIGNATURE="$(mktemp --tmpdir)"
CERTIFICATE="$(mktemp --tmpdir)"
TLOG_ENTRY="$(mktemp --tmpdir)"
cleanup() {
    [ -o xtrace ] && echo -e "📜 \033[1mCosign logs\033[0m" && kubectl logs sign-blob --all-containers

    rm -f "${LOGS}" "${SIGNATURE}" "${CERTIFICATE}" "${TLOG_ENTRY}"
    kubectl delete pod sign-blob > /dev/null 2>&1 || true
}
trap cleanup exit

kubectl run sign-blob \
    --quiet \
    --stdin \
    --attach \
    --image="${IMAGE}" \
    --env=SSL_CERT_FILE=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    --override-type=strategic \
    --overrides='{
        "apiVersion": "v1",
        "spec": {
            "initContainers": [
                {
                    "name": "cosign-initialize",
                    "image": "'"${IMAGE}"'",
                    "command": [
                        "cosign",
                        "initialize",
                        "--mirror",
                        "http://tuf-server.tuf-system.svc.cluster.local",
                        "--root",
                        "http://tuf-server.tuf-system.svc.cluster.local/root.json"
                    ],
                    "volumeMounts": [
                        {
                            "name": "sigstore",
                            "mountPath": "'"${SIGSTORE_CONF}"'"
                        }
                    ]
                }
            ],
            "containers":[
                {
                    "name": "sign-blob",
                    "volumeMounts": [
                        {
                            "name": "sigstore",
                            "mountPath": "'"${SIGSTORE_CONF}"'"
                        }
                    ]
                }
            ],
            "volumes": [
                {
                    "name": "sigstore",
                    "emptyDir": {}
                }
            ]
        }
    }' \
    -- \
    sign-blob \
    --oidc-issuer https://kubernetes.default.svc.cluster.local \
    --fulcio-url http://fulcio-server.fulcio-system.svc.cluster.local \
    --identity-token /var/run/secrets/kubernetes.io/serviceaccount/token \
    --rekor-url http://rekor-server.rekor-system.svc.cluster.local \
    --yes \
    --output-file=/dev/fd/1 \
    /dev/fd/0 < "$1" 2> "${LOGS}" > "${SIGNATURE}"

echo -e "🎗️ \033[1mCertificate\033[0m"
sed -n "/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p" "${LOGS}" > "${CERTIFICATE}"
cat "${CERTIFICATE}"

echo -e "📝 \033[1mSignature\033[0m"
cat "${SIGNATURE}"

echo -e "🪵 \033[1mSignature tlog entry\033[0m"
rekor-cli get --rekor_server http://rekor.localhost --log-index "$(sed -r -n -e 's/tlog entry created with index: ([0-9]+)/\1/p' "${LOGS}")" > "${TLOG_ENTRY}"
cat "${TLOG_ENTRY}"

echo -e "🔍 \033[1mVerifying signature\033[0m"
SSL_CERT_FILE=<(kubectl get cm kube-root-ca.crt -o jsonpath="{['data']['ca\.crt']}") \
SIGSTORE_REKOR_PUBLIC_KEY=<(curl -s http://rekor.localhost/api/v1/log/publicKey) \
SIGSTORE_CT_LOG_PUBLIC_KEY_FILE=<(kubectl get secret ctlog-public-key -o jsonpath='{.data.public}'|base64 -d) \
    cosign verify-blob \
    --certificate "${CERTIFICATE}" \
    --certificate-chain <(kubectl -n fulcio-system get secret fulcio-server-secret -o jsonpath='{.data.cert}'|base64 -d) \
    --certificate-identity-regexp '.*' \
    --certificate-oidc-issuer https://kubernetes.default.svc.cluster.local \
    --rekor-url https://rekor.localhost \
    --signature "${SIGNATURE}" \
    "$1"
