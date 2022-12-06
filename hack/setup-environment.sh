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

ROOT=$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P )
function handle_error {
  printf '\033[31mERROR\033[0m on line #%s\n\033[1mCommand:\033[0m %s\n' "$(caller)" "${BASH_COMMAND}"
  exit 1
}
trap handle_error ERR

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
  - containerPort: 5000
    hostPort: 5000
    protocol: TCP
EOF
else
  echo -e "Updating the existing \033[1m${KIND_CLUSTER_NAME}\033[0m cluster"
fi

kubectl cluster-info --context kind-ec

# We need the full git id and from the go.mod we get the short (12 character),
# so we clone to convert the short to the full lenght one.
# This can be overriden by specifying the ECC_VERSION environment variable
# beforehand
TKN_VERSION="${TKN_VERSION:-$(cd "${ROOT}/.." && go list -f '{{.Version}}' -m github.com/tektoncd/pipeline)}"
if [ -z "${ECC_VERSION:-}" ]; then
  SHORT_REV=$(cd "${ROOT}/.." && go list -f '{{slice .Version 22}}' -m github.com/hacbs-contract/enterprise-contract-controller/api)
  ECC_VERSION=$(
    TMP_ECC_GIT=$(mktemp -d)
    trap 'rm -rf "${TMP_ECC_GIT}"' EXIT
    cd "${TMP_ECC_GIT}"
    git clone -q --bare https://github.com/hacbs-contract/enterprise-contract-controller.git "${TMP_ECC_GIT}"
    git show -s --pretty=format:%H "${SHORT_REV}"
  )
else
  echo -e "Using version \033[1m${ECC_VERSION}\033[0m of enterprise-contract-controller"
fi

# Install Tekton Pipelines and Webhook controllers
echo -e '✨ \033[1mInstalling Tekton pipelines\033[0m'
(
  TMP_TKN_KUS=$(mktemp -d)
  trap 'rm -rf "${TMP_TKN_KUS}"' EXIT
  TKN_VERSION="${TKN_VERSION}" envsubst < "${ROOT}/tekton/kustomization.yaml" > "${TMP_TKN_KUS}/kustomization.yaml"
  kubectl kustomize "${TMP_TKN_KUS}" | kubectl apply -f -
)

# Setup the public key from hack/cosign.pub and create the
# EnterpriseContractPolicy custom resource
echo -e '✨ \033[1mInstalling enterprise-contract-controller\033[0m'
(
  TMP_ECC_KUS=$(mktemp -d)
  trap 'rm -rf "${TMP_ECC_KUS}"' EXIT
  cp -R "${ROOT}/ecc/"* "${TMP_ECC_KUS}"
  ECC_VERSION="${ECC_VERSION}" envsubst < "${ROOT}/ecc/kustomization.yaml" > "${TMP_ECC_KUS}/kustomization.yaml"
  kubectl kustomize "${TMP_ECC_KUS}" | kubectl apply -f -
)

# Deploy local image registry we can push from the host and pull from within
# kind
echo -e '✨ \033[1mInstalling image registry\033[0m'
kubectl kustomize "${ROOT}/registry" | kubectl apply -f -

# Wait for the image registry to be deployed before we build and push the images
# to it
kubectl -n image-registry wait deployment -l "app.kubernetes.io/name=registry" --for=condition=Available --timeout=30s

# Build and push the images to the local image registry
echo -e '✨ \033[1mBuilding images\033[0m'
make --no-print-directory -C "${ROOT}/.." push-image IMAGE_REPO=localhost:5000/ec PODMAN_OPTS=--tls-verify=false
make --no-print-directory -C "${ROOT}/.." task-bundle "TASK_REPO=localhost:5000/ec-task-bundle" TASK=<(yq e ".spec.steps[].image? = \"127.0.0.1:5000/ec:latest-$(go env GOOS)-$(go env GOARCH)\"" "${ROOT}"/../task/*/verify-enterprise-contract.yaml)

# Wait for Tekton Pipelines & Webhook controllers to be ready, we do this after
# installing Tekton and building the images to let some time pass and we don't
# block the image build doing nothing
kubectl -n tekton-pipelines wait deployment -l "pipeline.tekton.dev/release=${TKN_VERSION}" --for=condition=Available --timeout=180s

# Create the "work" namespace and set the required RBAC, v-e-c Tekton Tasks need
# to be run within this namespace
echo -e '✨ \033[1mCreating the "work" namespace\033[0m'
kubectl kustomize "${ROOT}/work" | kubectl apply -f -
kubectl -n work create secret generic cosign-public-key --from-file=cosign.pub="${ROOT}/cosign.pub" -o yaml --dry-run=client | kubectl apply -f -

# Set the current context's namespace to "work"
kubectl config set-context --current --namespace=work

echo -e '✨ \033[1mDone\033[0m'
echo -e "The \033[1mwork\033[0m namespace is set as current and prepared to run the verify-enterprise-contract Tekton Task."
echo -e "The verify-enterprise-contract Tekton Task can be pulled from \033[1mregistry.image-registry.svc.cluster.local:5000/ec-task-bundle\033[0m"
echo -e "Image push can be performed from the host machine to image registry at \033[1mlocalhost:5000\033[0m"
