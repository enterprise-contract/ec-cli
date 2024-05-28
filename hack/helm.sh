#!/usr/bin/env bash
# Copyright The Enterprise Contract Contributors
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

# Runs helm with the version provided via tools/go.mod

set -o errexit
set -o pipefail
set -o nounset
set -o errtrace

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
K8_VERSION_MAJOR=$(kubectl version -o json |jq -r .serverVersion.major)
K8_VERSION_MINOR=$(kubectl version -o json |jq -r .serverVersion.minor)
LDFLAGS="-X helm.sh/helm/v3/pkg/chartutil.k8sVersionMajor=${K8_VERSION_MAJOR} -X helm.sh/helm/v3/pkg/chartutil.k8sVersionMinor=${K8_VERSION_MINOR}"
go run -modfile "${ROOT}/tools/go.mod" -ldflags "${LDFLAGS}" helm.sh/helm/v3/cmd/helm --debug "$@"
