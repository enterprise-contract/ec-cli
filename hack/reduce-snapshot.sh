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
#
# This script attempts to reduce a snapshot to a single component
# It determines the component via a custom resource's labels.
# It requires that the following environment variables be defined:
#
# - SINGLE_COMPONENT: true if single component mode is enabled.
# - SNAPSHOT: String representation of Snapshot
# - CUSTOM_RESOURCE: Custom Resource to query for built component in Snapshot
# - CUSTOM_RESOURCE_NAMESPACE: Namespace where Custom Resource is found
# - SNAPSHOT_PATH: The location to place the reduced Snapshot json file

set -o errexit
set -o nounset
set -o pipefail

# verify if in json form
SNAPSHOT="$(cat "${SNAPSHOT}" 2> /dev/null || echo "${SNAPSHOT}")"
[[ ! "${SNAPSHOT}" =~ ^\s*\{ ]] && echo 'Error: Cannot load snapshot from JSON string or file' && exit 1

echo "Single Component mode? ${SINGLE_COMPONENT}"
if [ "${SINGLE_COMPONENT}" == "true" ]; then

  CR_NAMESPACE_ARG=
  if [ "${CUSTOM_RESOURCE_NAMESPACE}" != "" ]; then
    CR_NAMESPACE_ARG="-n ${CUSTOM_RESOURCE_NAMESPACE}"
  fi
  SNAPSHOT_CREATION_TYPE=$(kubectl get "$CUSTOM_RESOURCE" ${CR_NAMESPACE_ARG:+$CR_NAMESPACE_ARG} -ojson \
      | jq -r '.metadata.labels."test.appstudio.openshift.io/type" // ""')
  SNAPSHOT_CREATION_COMPONENT=$(kubectl get "$CUSTOM_RESOURCE" ${CR_NAMESPACE_ARG:+$CR_NAMESPACE_ARG} -ojson \
      | jq -r '.metadata.labels."appstudio.openshift.io/component" // ""')

  echo "SNAPSHOT_CREATION_TYPE: ${SNAPSHOT_CREATION_TYPE}"
  echo "SNAPSHOT_CREATION_COMPONENT: ${SNAPSHOT_CREATION_COMPONENT}"
  if [ "${SNAPSHOT_CREATION_TYPE}" == "component" ] && [ "${SNAPSHOT_CREATION_COMPONENT}" != "" ]; then
    echo "Single Component mode is ${SINGLE_COMPONENT} and Snapshot type is component"

    SNAPSHOT=$(echo "${SNAPSHOT}" | jq --arg component "${SNAPSHOT_CREATION_COMPONENT}" \
    'del(.components[] | select(.name != $component))')

    ## make sure we still have 1 component
    COMPONENT_COUNT=$(echo "$SNAPSHOT" | jq -r '[ .components[] ] | length')
    echo "COMPONENT_COUNT: ${COMPONENT_COUNT}"
    if [ "${COMPONENT_COUNT}" != "1" ] ; then
      echo "Error: Reduced Snapshot has ${COMPONENT_COUNT} components. It should contain 1"
      echo "       Verify that the Snapshot contains the built component: ${SNAPSHOT_CREATION_COMPONENT}"
      exit 1
    fi
  fi
fi

# we need to create snapshot file to be passed to later stages.
echo "${SNAPSHOT}" | jq '.' | tee "${SNAPSHOT_PATH}"
