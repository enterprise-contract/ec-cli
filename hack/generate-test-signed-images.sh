#!/usr/bin/env bash
# Copyright The Enterprise Contract Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# This script is used to generate the OCI image used during the keyless acceptance tests. It uses
# the staging version of Sigstore to sign and attest the image. It also uses WireMock to record the
# interactions with TUF API. Finally, all data is copied over to the proper places in this git repo.
# Be sure to commit them.
#
# Usage:
#   ./hack/generate-test-signed-images.sh

set -euo pipefail

errors=false

export REKOR_URL='https://rekor.sigstage.dev'
export FULCIO_URL='https://fulcio.sigstage.dev'
export ISSUER_URL='https://oauth2.sigstage.dev/auth'
export TUF_MIRROR='https://tuf-repo-cdn.sigstage.dev'
export TUF_ROOT_URL='https://raw.githubusercontent.com/sigstore/root-signing-staging/main/metadata/root.json'

CERTIFICATE_IDENTITY='luizcarvalho85@gmail.com'
CERTIFICATE_ISSUER='https://github.com/login/oauth'

# Check if the docker registry already exists
set +e
docker inspect registry &> /dev/null
registry_exists="$?"
set -e
if [[ "${registry_exists}" -eq "0" ]]; then
    echo '🛑 The registry already exists. Delete it first:'
    echo -e '\tdocker rm -f registry'
    errors=true
fi

$errors && exit 1

docker run -it -d -p 5000:5000 --name registry registry:2

WORKDIR="$(mktemp -d)"
echo "Using WORKDIR at ${WORKDIR}"

LOCAL_ROOT="${WORKDIR}/root.json"

export TUF_ROOT="${WORKDIR}/tuf_root"
mkdir -p "${TUF_ROOT}"

function make_image() {
    repo='registry.local:5000/sigstore/testimage'
    container="$(buildah from scratch)"
    image="$(buildah commit "${container}")"
    digestfile="$(mktemp)"
    buildah push --tls-verify=false --digestfile "${digestfile}" \
        "${image}" "docker://${repo}:latest"
    printf "${repo}@$(< "${digestfile}")"
}

# Make cosign use staging Sigstore deployment:
#   https://docs.sigstore.dev/system_config/public_deployment/ (some URLs are out of date in the docs)
curl -L https://raw.githubusercontent.com/sigstore/root-signing-staging/main/metadata/root.json \
    -o "${WORKDIR}/root.json"

cosign initialize --mirror "${TUF_MIRROR}" --root "${LOCAL_ROOT}"

# Generate image
image="$(make_image)"
echo "✅ New image created: ${image}"

# Sign image
cosign sign --allow-insecure-registry -y \
    --oidc-issuer "${ISSUER_URL}" \
    --rekor-url "${REKOR_URL}" \
    --fulcio-url "${FULCIO_URL}" \
    "${image}"
echo '✅ Image signed'

# Verify the signature is correct
cosign verify --allow-insecure-registry \
    --certificate-identity "${CERTIFICATE_IDENTITY}" \
    --certificate-oidc-issuer "${CERTIFICATE_ISSUER}" \
    "${image}" > /dev/null
echo '✅ Image signature verified'

# Generate provenance for the image
provenance='
{
  "builder": {
    "id": "https://tekton.dev/chains/v2"
  },
  "buildType": "tekton.dev/v1/PipelineRun",
  "invocation": {},
  "metadata": {
    "buildStartedOn": "2023-03-22T19:38:01Z",
    "buildFinishedOn": "2023-03-22T19:41:05Z",
    "completeness": {
      "parameters": false,
      "environment": false,
      "materials": false
    },
    "reproducible": false
  },
  "materials": []
}
'

# Attest the image with SLSA Provenance
cosign attest --allow-insecure-registry -y \
    --predicate <(echo "${provenance}") \
    --type slsaprovenance \
    --oidc-issuer "${ISSUER_URL}" \
    --fulcio-url $FULCIO_URL \
    --rekor-url $REKOR_URL \
    "${image}"
echo '✅ Image attested'

# Verify the attestation is correct
cosign verify-attestation --allow-insecure-registry \
    --type slsaprovenance \
    --certificate-identity "${CERTIFICATE_IDENTITY}" \
    --certificate-oidc-issuer "${CERTIFICATE_ISSUER}" \
    "${image}"
echo '✅ Image attestation verified'

# Copy over required files for acceptance tests
rm -rf ./acceptance/image/testimage/*
cosign save "${image}" --dir ./acceptance/image/testimage
cp "${LOCAL_ROOT}" ./acceptance/tuf/

./hack/update-tuf-root-recordings.sh

echo "
Image: ${image}
WORKDIR: ${WORKDIR}

You can safely remove the docker registry:
    docker rm -f registry
"
