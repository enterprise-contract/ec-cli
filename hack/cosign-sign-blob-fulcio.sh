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

# Installs Tekton Pipeline, the Enterprise Contract Policy custom resource and
# loads the Tekton Task bundle and the container image with the `ec` command
# line needed by the task to execute

set -o errexit
set -o pipefail
set -o nounset
set -o errtrace

if (( $# != 1 )); then
    echo "usage $0 <file to sign>"
    exit 1
fi

LOGS="$(mktemp --tmpdir)"
SIGNATURE="$(mktemp --tmpdir)"
CERTIFICATE="$(mktemp --tmpdir)"
TLOG_ENTRY="$(mktemp --tmpdir)"
cleanup() {
    rm -f "${LOGS}" "${SIGNATURE}" "${CERTIFICATE}" "${TLOG_ENTRY}"
}
trap cleanup exit

kubectl get secret ctlog-public-key > /dev/null 2>&1 || kubectl -n ctlog-system get secret ctlog-public-key -o yaml | yq ".metadata.namespace |= \"$(kubectl get sa -o=jsonpath='{.items[0]..metadata.namespace}')\"" | kubectl apply -f -

kubectl run sign-blob \
    --quiet \
    --rm \
    --stdin \
    --attach \
    --image=gcr.io/projectsigstore/cosign \
    --env=SSL_CERT_FILE=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    --env=SIGSTORE_CT_LOG_PUBLIC_KEY_FILE=/ctlog/public \
    --override-type=strategic \
    --overrides='{
        "apiVersion": "v1",
        "spec": {
            "containers":[
                {
                    "name": "sign-blob",
                    "volumeMounts": [
                        {
                            "name": "ctlog-public-key",
                            "mountPath": "/ctlog",
                            "secretName": "ctlog-public-key"
                        }
                    ]
                }
            ],
            "volumes": [
                {
                    "secret": {
                        "defaultMode": 420,
                        "name": "ctlog-public-key",
                        "secretName": "ctlog-public-key"
                    },
                    "name": "ctlog-public-key"
                }
            ]
        }
    }' \
    -- \
    sign-blob \
    --oidc-issuer https://kubernetes.default.svc.cluster.local \
    --fulcio-url=http://fulcio-server.fulcio-system.svc.cluster.local \
    --identity-token /var/run/secrets/kubernetes.io/serviceaccount/token \
    --rekor-url http://rekor-server.rekor-system.svc.cluster.local \
    --yes \
    --output-file=/dev/fd/1 \
    /dev/fd/0 < "$1" 2> "${LOGS}" > "${SIGNATURE}"

sed -n "/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p" "${LOGS}" > "${CERTIFICATE}"

rekor-cli get --rekor_server http://rekor.localhost --log-index "$(sed -r -n -e 's/tlog entry created with index: ([0-9]+)/\1/p' "${LOGS}")" > "${TLOG_ENTRY}"

echo -e "📜 \033[1mCosign logs\033[0m"
cat "${LOGS}"

echo -e "🎗️ \033[1mCertificate\033[0m"
cat "${CERTIFICATE}"

echo -e "📝 \033[1mSignature\033[0m"
cat "${SIGNATURE}"

echo -e "🪵 \033[1mSignature tlog entry\033[0m"
cat "${TLOG_ENTRY}"

echo -e "🔍 \033[1mVerifying signature\033[0m"
SSL_CERT_FILE=<(kubectl get cm kube-root-ca.crt -o jsonpath="{['data']['ca\.crt']}") \
SIGSTORE_REKOR_PUBLIC_KEY=<(curl -s http://rekor.localhost/api/v1/log/publicKey) \
    cosign verify-blob \
    --certificate "${CERTIFICATE}" \
    --certificate-chain <(kubectl -n fulcio-system get secret fulcio-server-secret -o jsonpath='{.data.cert}'|base64 -d) \
    --certificate-identity-regexp '.*' \
    --certificate-oidc-issuer https://kubernetes.default.svc.cluster.local \
    --insecure-ignore-sct \
    --rekor-url https://rekor.localhost \
    --signature "${SIGNATURE}" \
    "$1"
