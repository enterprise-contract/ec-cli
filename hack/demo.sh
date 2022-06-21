#!/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
set -o posix

HACK_DIR="$(dirname "${BASH_SOURCE[0]}")"
EC="${HACK_DIR}/../dist/ec_$(go env GOOS)_$(go env GOARCH)"

echo "Using ec version $("${EC}" version)"

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

for IMG in 'quay.io/hacbs-contract-demo/single-nodejs-app:877418e' 'quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f' 'quay.io/hacbs-contract-demo/single-container-app:62c06bf'; do
  printf "\n🩺 Evaluating policy for %s\n\n" "${IMG}"
  echo "💲 ${EC}" eval --image "${IMG}" --public-key "${HACK_DIR}/cosign.pub" --policy demo/ec-demo
  "${EC}" eval --image "${IMG}" --public-key "${HACK_DIR}/cosign.pub" --policy demo/ec-demo
done
