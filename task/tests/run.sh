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

set -o errexit
set -o pipefail
set -o nounset

# source variables to test
ROOT=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

TASK_BUNDLE_REF="${TASK_BUNDLE_REF:-quay.io/hacbs-contract/ec-task-bundle:snapshot}"

TASKRUN=verify-enterprise-contract-taskrun
TASKRUN_FILE="${TASKRUN}.yaml"
TASK_VERSION="${TASK_VERSION:-0.1}"
TASK_DIR="${ROOT}/../${TASK_VERSION}"
TEST_DIR="${TASK_DIR}/tests"

# run and wait for taskRun
kubectl apply -f "${TEST_DIR}/ecp-policy.yaml"
TASK_RUN_NAME=$(TASK_BUNDLE_REF="${TASK_BUNDLE_REF}" envsubst < "${TEST_DIR}/${TASKRUN_FILE}" |kubectl create -o name -f -)
echo -n Waiting for the task to finish
while ! kubectl wait "${TASK_RUN_NAME}" -o=jsonpath='{.nonexistant}' --for=condition=Succeeded --timeout=1s 2>/dev/null && ! kubectl wait "${TASK_RUN_NAME}" -o=jsonpath='{.nonexistant}' --for=condition=Succeeded=false --timeout=1s 2>/dev/null; do
  echo -n .
done
status=$(kubectl get "${TASK_RUN_NAME}" -o jsonpath='{.status.conditions[*].status}')

if [[ "$status" == "False" ]]; then
  echo
  echo -e "💣 \033[31;1mTask ${TASK_RUN_NAME} failed\033[0m"
  echo -e '\033[4;1mTekton TaskRun description\033[0m'
  go run -modfile internal/tools/go.mod github.com/tektoncd/cli/cmd/tkn tr describe "${TASK_RUN_NAME#*/}"
  echo -e '\033[4;1mPod logs\033[0m'
  POD_NAME=$(kubectl get "${TASK_RUN_NAME}" -o jsonpath='{.status.podName}')
  kubectl logs "${POD_NAME}" --all-containers=true
  echo -e "\033[4;1mkubectl describe ${TASK_RUN_NAME}\033[0m"
  kubectl describe "${TASK_RUN_NAME}"
  exit 1
else
  echo OK
fi
