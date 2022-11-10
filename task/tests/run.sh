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

# source variables to test
ROOT=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

OCI_REPO="${OCI_REPO:-quay.io/hacbs-contract/verify-enterprise-contract}"

TASK=verify-enterprise-contract
TASK_FILE="${TASK}.yaml"
TASKRUN=verify-enterprise-contract-taskrun
TASKRUN_FILE="${TASKRUN}.yaml"
TASK_VERSION="${TASK_VERSION:-0.1}"
TASK_DIR="${ROOT}/../${TASK_VERSION}"
TEST_DIR="${TASK_DIR}/tests"

# run and wait for taskRun
kubectl apply -f "${TEST_DIR}/ecp-policy.yaml"
kubectl apply -f "${TASK_DIR}/${TASK_FILE}"
tr=$(kubectl create -f "${TEST_DIR}/${TASKRUN_FILE}" |awk '{print $1}')
kubectl wait $tr --for=condition=Succeeded --timeout=90s
status=$(kubectl get $tr -o jsonpath='{.status.conditions[*].status}')

if [[ "$status" == "False" ]]; then
  echo "task {$tr} failed"
  echo "debugging info"
  kubectl describe $tr
  exit 1
fi

tkn bundle push ${OCI_REPO}:$TASK_VERSION -f "${TASK_DIR}/${TASK_FILE}"
