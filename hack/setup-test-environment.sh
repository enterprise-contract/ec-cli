#!/usr/bin/env bash
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

# Installs Tekton Pipeline, the Enterprise Contract Policy custom resource and
# loads the Tekton Task bundle and the container image with the `ec` command
# line needed by the task to execute

set -o errexit
set -o pipefail
set -o nounset
set -o errtrace

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

function handle_error {
  printf '\033[31mERROR\033[0m on line #%s\n\033[1mCommand:\033[0m %s\n' "$(caller)" "${BASH_COMMAND}"
  exit 1
}
trap handle_error ERR

KUSTOMIZE="go run -modfile "${ROOT}/tools/go.mod" sigs.k8s.io/kustomize/kustomize/v4 build --enable-exec --enable-alpha-plugins"

# The name of the Kind cluster
KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-ec}

# Create the kind cluster if it doesn't exist
if ! kind get clusters | grep -q "${KIND_CLUSTER_NAME}"; then
  cat <<EOF | kind create cluster --name="${KIND_CLUSTER_NAME}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        "service-node-port-range": "1-65535"
  extraPortMappings:
  - containerPort: ${REGISTRY_PORT:-5000}
    hostPort: ${REGISTRY_PORT:-5000}
    protocol: TCP
EOF
else
  echo -e "Updating the existing \033[1m${KIND_CLUSTER_NAME}\033[0m cluster"
fi

kubectl cluster-info --context kind-ec

echo -e '✨ \033[1mInstalling test resources\033[0m'
${KUSTOMIZE} "${ROOT}/hack/test" | kubectl apply -f -

# Wait for the image registry to be deployed before we build and push the images
# to it
echo -e '✨ \033[1mWaiting for the image registry to become available\033[0m'
kubectl -n image-registry wait deployment -l "app.kubernetes.io/name=registry" --for=condition=Available --timeout=60s

# Build and push the images to the local image registry
echo -e '✨ \033[1mBuilding images\033[0m'
make --no-print-directory -C "${ROOT}" push-image IMAGE_REPO="localhost:${REGISTRY_PORT:-5000}/ec" PODMAN_OPTS=--tls-verify=false
make --no-print-directory -C "${ROOT}" task-bundle "TASK_REPO=localhost:${REGISTRY_PORT:-5000}/ec-task-bundle" TASK=<(yq e ".spec.steps[].image? = \"127.0.0.1:${REGISTRY_PORT:-5000}/ec:latest-$(go env GOOS)-$(go env GOARCH)\"" "${ROOT}"/task/*/verify-enterprise-contract.yaml)

# Wait for Tekton Pipelines & Webhook controllers to be ready, we do this after
# installing Tekton and building the images to let some time pass and we don't
# block the image build doing nothing
echo -e '✨ \033[1mWaiting for Tekton Pipelines to become available\033[0m'
kubectl -n tekton-pipelines wait deployment -l "app.kubernetes.io/part-of=tekton-pipelines" --for=condition=Available --timeout=180s

# Set the current context's namespace to "work"
kubectl config set-context --current --namespace=work

echo -e '✨ \033[1mDone\033[0m'
echo -e "The \033[1mwork\033[0m namespace is set as current and prepared to run the verify-enterprise-contract Tekton Task."
echo -e "The verify-enterprise-contract Tekton Task can be pulled from \033[1mregistry.image-registry.svc.cluster.local:${REGISTRY_PORT:-5000}/ec-task-bundle\033[0m"
echo -e "Image push can be performed from the host machine to image registry at \033[1mlocalhost:${REGISTRY_PORT:-5000}\033[0m"
