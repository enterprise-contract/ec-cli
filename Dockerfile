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

## Build

FROM docker.io/library/golang:1.21 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /build

# Copy just the mod file for better layer caching when building locally
COPY go.mod go.sum ./
RUN go mod download

# Now copy everything including .git
COPY . .

RUN /build/build.sh "${TARGETOS}_${TARGETARCH}"

# Extract this so we can download the matching cosign version below
RUN go list --mod=readonly -f '{{.Version}}' -m github.com/sigstore/cosign/v2 | tee cosign_version.txt

## Downloads

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.4@sha256:2636170dc55a0931d013014a72ae26c0c2521d4b61a28354b3e2e5369fa335a3 AS download

ARG TARGETOS
ARG TARGETARCH

WORKDIR /download

COPY --from=build /build/cosign_version.txt /download/

# Download the matching version of cosign
RUN COSIGN_VERSION=$(cat /download/cosign_version.txt) && \
    curl -sLO https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-${TARGETOS}-${TARGETARCH} && \
    curl -sLO https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign_checksums.txt && \
    sha256sum --check <(grep -w "cosign-${TARGETOS}-${TARGETARCH}" < cosign_checksums.txt) && \
    mv "cosign-${TARGETOS}-${TARGETARCH}" cosign && \
    chmod +x cosign

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.4@sha256:2636170dc55a0931d013014a72ae26c0c2521d4b61a28354b3e2e5369fa335a3

ARG TARGETOS
ARG TARGETARCH

COPY --from=download /download/cosign /usr/local/bin/cosign
RUN cosign version

RUN microdnf upgrade --assumeyes --nodocs --setopt=keepcache=0 --refresh && microdnf -y --nodocs --setopt=keepcache=0 install git-core jq

# Copy the one ec binary that can run in this container
COPY --from=build "/build/dist/ec_${TARGETOS}_${TARGETARCH}" /usr/local/bin/ec

ENTRYPOINT ["/usr/local/bin/ec"]
