#!/bin/bash
# For backwards compatibility with older task definitions that might still
# try to run `cosign initialize`

set -euo pipefail

if [ "${1:-""}" != "initialize" ]; then
  echo "Wrapper script supports cosign initialize only!"
  exit 1
fi

ec sigstore "$@"
