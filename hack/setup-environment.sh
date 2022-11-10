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

#!/usr/bin/env bash

ROOT=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
# max version that works with the kind cluster (container-tools/kind-action@v2)
TKN_VERSION="${TKN_VERSION:-v0.38.4}"

# install tekton and wait for controllers to start
kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/previous/$TKN_VERSION/release.yaml
kubectl wait pods -n tekton-pipelines -l pipeline.tekton.dev/release=$TKN_VERSION --for=condition=Ready --timeout=180s

# setup resources for the ec task to run
kubectl create secret generic cosign-public-key --from-file=cosign.pub="${ROOT}/cosign.pub"
kubectl kustomize https://github.com/hacbs-contract/enterprise-contract-controller/config/crd?ref=main | kubectl apply -f -

# rbac for everything to work
kubectl create clusterrole ecp-reader --verb=get,list --resource=enterprisecontractpolicy
kubectl create rolebinding ecp-binding --clusterrole=ecp-reader --serviceaccount=default:default --namespace=default
kubectl create role access-secrets --verb=get,list,watch,update,create --resource=secrets -n default
kubectl create rolebinding --role=access-secrets default-to-secrets --serviceaccount=default:default -n default
