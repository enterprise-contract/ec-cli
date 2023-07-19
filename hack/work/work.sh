#!/usr/bin/env bash
# Copyright Red Hat.
#
# Licensed under the Apache License, Version 2.0 (the "License");

#
# SPDX-License-Identifier: Apache-2.0

# Fetches the Tekton YAML descriptors for the version we depend on

set -o errexit
set -o pipefail
set -o nounset

NS="${WORK_NAMESPACE:-work}"

printf -- '---
apiVersion: v1
kind: Namespace
metadata:
  name: %s
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: work-namespace-name
  namespace: work
data:
  NAMESPACE: %s' "${NS}" "${NS}"
