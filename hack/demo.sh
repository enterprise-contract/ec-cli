#!/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
set -o posix

HACK_DIR="$(dirname "${BASH_SOURCE[0]}")"
EC="${HACK_DIR}/../dist/ec"

if [[ ! -x "${EC}" ]]; then
  (cd "${HACK_DIR}/.."; make)
fi

kubectl create namespace demo --dry-run=client -o yaml |kubectl apply -f -

kubectl create -o yaml --dry-run=client -f - <<EOF | kubectl apply -f -
apiVersion: appstudio.redhat.com/v1alpha1
kind: EnterpriseContractPolicy
metadata:
  namespace: demo
  name: ec-demo
spec:
  description: Demo Enterprise Contract policy configuration
  exceptions:
    nonBlocking:
    - not_useful
    - test:conftest-clair
  sources:
  - git:
      repository: github.com/simonbaird/ec-policies//policies
      revision: pr-att-test-results
EOF

for IMG in 'quay.io/zregvart_redhat/single-nodejs-app:2e92018' 'quay.io/zregvart_redhat/spring-petclinic:dc80a7f' 'quay.io/zregvart_redhat/single-container-app:37daed8'; do
  printf "\n🩺 Evaluating policy for %s\n\n" "${IMG}"
  echo "💲 ${EC}" eval --image "${IMG}" --public-key "${HACK_DIR}/cosign.pub" --policy demo/ec-demo
  "${EC}" eval --image "${IMG}" --public-key "${HACK_DIR}/cosign.pub" --policy demo/ec-demo
done
