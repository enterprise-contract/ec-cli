#!/usr/bin/env bash

ROOT=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

# install tekton and wait for controllers to start
tekton_version=v0.38.4 # max version that works with the kind cluster (container-tools/kind-action@v2)
kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/previous/$tekton_version/release.yaml
kubectl wait pods -n tekton-pipelines -l pipeline.tekton.dev/release=$tekton_version --for=condition=Ready --timeout=180s

# setup resources for the ec task to run
kubectl create secret generic cosign-public-key --from-file=cosign.pub="${ROOT}/../hack/cosign.pub"
kustomize build https://github.com/hacbs-contract/enterprise-contract-controller/config/crd?ref=main | kubectl apply -f -
kubectl create -f "${ROOT}/ecp-policy.yaml"
kubectl apply -f "${ROOT}/verify-enterprise-contract.yaml"
kubectl create -f "${ROOT}/verify-enterprise-contract-taskrun.yaml"

# rbac for everything to work
kubectl create clusterrole ecp-reader --verb=get,list --resource=enterprisecontractpolicy
kubectl create rolebinding ecp-binding --clusterrole=ecp-reader --serviceaccount=default:default --namespace=default
kubectl create role access-secrets --verb=get,list,watch,update,create --resource=secrets -n default
kubectl create rolebinding --role=access-secrets default-to-secrets --serviceaccount=default:default -n default

# run and wait for taskRun
tr=$(kubectl create -f "${ROOT}/verify-enterprise-contract-taskrun.yaml" |awk '{print $1}')
kubectl wait $tr --for=condition=Succeeded --timeout=90s
status=$(kubectl get $tr -o jsonpath='{.status.conditions[*].status}')

if [[ "$status" == "False" ]]; then
  echo "failed"
  exit 1
else 
  exit 0
fi
