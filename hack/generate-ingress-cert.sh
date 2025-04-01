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

# Requests a TLS certificate for the Nginx Ingress with wildcard certificate
# (*.localhost)

set -o errexit
set -o pipefail
set -o nounset
set -o errtrace

KEY="$(mktemp --tmpdir)"
REQ="$(mktemp --tmpdir)"
CER="$(mktemp --tmpdir)"
cleanup() {
    rm -f "${KEY}" "${REQ}" "${CER}"
}
trap cleanup EXIT

openssl req -new -subj "/O=system:nodes/CN=system:node:ingress" -addext "subjectAltName=DNS:*.localhost" -nodes -keyout "${KEY}" -out "${REQ}"

kubectl delete csr wildcard.localhost >/dev/null 2>&1 || true

cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: wildcard.localhost
spec:
  request: $(base64 --wrap=0 <"${REQ}")
  signerName: kubernetes.io/kubelet-serving
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF

kubectl certificate approve wildcard.localhost

kubectl get csr wildcard.localhost -o jsonpath='{.status.certificate}' | base64 --decode > "${CER}"

kubectl -n ingress-nginx create secret tls wildcard-localhost  --key "${KEY}" --cert "${CER}" --dry-run=client -o yaml | kubectl apply -f -
