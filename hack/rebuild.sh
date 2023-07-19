#!/usr/bin/env bash
# Copyright Red Hat.
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

# Rebuilds the images, stores the image references in images.txt and updates the
# cosign.pub. Requires a running Tekton and Tekton Chains and the usual
# utilities: kubectl & openssl; and access to an operating RHTAP cluster.

set -o errexit
set -o pipefail
set -o nounset

HACK_DIR="$(dirname "${BASH_SOURCE[0]}")"

# The default in RHTAP
PIPELINE_SERVICE_ACCOUNT=pipeline

# What pipeline bundle to use
PIPELINE_BUNDLE=quay.io/redhat-appstudio-tekton-catalog/pipeline-hacbs-docker-build:devel

# Where to push the image(s)
IMAGE_REPOSITORY=quay.io/hacbs-contract-demo

# If RHTAP is not setup, there might not be a appstudio PVC, this creates if if
# it already doesn't exist
kubectl get pvc appstudio -o name > /dev/null 2>&1 || kubectl create -o yaml --dry-run=client -f - << EOF | kubectl apply -f - >&2
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: appstudio
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
  volumeMode: Filesystem
EOF

# Might require that the pull secret is set for the pipeline service account,
# the secret named redhat-appstudio-registry-pull-secret is pre-created and
# could be empty in RHTAP, so it needs to be recreated from the local Docker
# configuration
{
    kubectl get secret redhat-appstudio-registry-pull-secret -o name > /dev/null 2>&1 && [ -n "$(kubectl get secret redhat-appstudio-registry-pull-secret -o jsonpath='{.data}')" ]
} || {
    kubectl delete secret redhat-appstudio-registry-pull-secret 2> /dev/null || true
    kubectl create secret docker-registry redhat-appstudio-registry-pull-secret --from-file=.dockerconfigjson="${HOME}/.docker/config.json" --dry-run=client -o yaml | kubectl apply -f - >&2
    kubectl patch sa pipeline --type json -p '[{"op":"add","path":"/imagePullSecrets/-","value":{"name":"redhat-appstudio-registry-pull-secret"}},{"op":"add","path":"/secrets/-","value":{"name":"redhat-appstudio-registry-pull-secret"}}]' >&2
    kubectl patch clusterrolebinding shared-resource-redhat-appstudio-staginguser --type json -p "[{\"op\":\"add\",\"path\":\"/subjects/-\",\"value\":{\"kind\":\"ServiceAccount\",\"name\":\"pipeline\",\"namespace\":\"$(ns=$(kubectl config current-context); echo "${ns%%/*}")\"}}]" >&2
}

function build() {
    local build_type=$1
    local git_repository=$2
    local image_repository=$3
    local dockerfile_path=${4:-Dockerfile}

    local name=${git_repository##*/}
    local pipeline_run
    pipeline_run="${name}-$(openssl rand --hex 8)"

    kubectl create -o yaml --dry-run=client -f - <<EOF | kubectl apply -f - >&2
apiVersion: tekton.dev/v1beta1
kind: PipelineRun
metadata:
  name: ${pipeline_run}
spec:
  params:
  - name: git-url
    value: '${git_repository}'
  - name: output-image
    value: '${image_repository}'
  - name: dockerfile
    value: '${dockerfile_path}'
  - name: path-context
    value: .
  pipelineRef:
    bundle: ${PIPELINE_BUNDLE}
    name: ${build_type}
  serviceAccountName: ${PIPELINE_SERVICE_ACCOUNT}
  timeout: 1h0m0s
  workspaces:
  - name: workspace
    persistentVolumeClaim:
      claimName: appstudio
    subPath: ${name}/build-$(date --iso-8601=s)
EOF

    kubectl wait --for=condition=Succeeded --for=condition=Succeeded=false --timeout=-1s "pipelinerun/${pipeline_run}" >&2

    echo "${image_repository}@$(kubectl get "pipelinerun/${pipeline_run}" -o jsonpath='{.status.pipelineResults[?(@.name=="IMAGE_DIGEST")].value}')"
}

IMAGES=$(
    # build <docker-build|nodejs-builder|java-builder> <git repository> <image repository>
    build docker-build https://github.com/jduimovich/single-container-app "${IMAGE_REPOSITORY}/single-container-app" &
    build nodejs-builder https://github.com/jduimovich/single-nodejs-app "${IMAGE_REPOSITORY}/single-nodejs-app" &
    # add more examples here

    # shellcheck disable=SC2046
    wait $(jobs -p)
)

echo "${IMAGES}" > "${HACK_DIR}/images.txt"

# shellcheck disable=SC2094
cat <<< "$(jq --rawfile images <(echo "$IMAGES") '.components |= [$images | capture("(?<containerImage>.*\/(?<name>.*)@.*)";"g")]' "${HACK_DIR}/application_snapshot.json")" > "${HACK_DIR}/application_snapshot.json"

# update cosign public key
kubectl get secret -n tekton-chains signing-secrets -o jsonpath='{.data.cosign\.pub}'|base64 -d > "${HACK_DIR}/work/cosign.pub"
