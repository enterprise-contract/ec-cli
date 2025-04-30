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

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.5@sha256:e1c4703364c5cb58f5462575dc90345bcd934ddc45e6c32f9c162f2b5617681c

ARG TARGETOS
ARG TARGETARCH

RUN microdnf upgrade --assumeyes --nodocs --setopt=keepcache=0 --refresh && microdnf -y --nodocs --setopt=keepcache=0 install git-core jq

# Copy the one ec binary that can run in this container
COPY --from=build "/build/dist/ec_${TARGETOS}_${TARGETARCH}" /usr/local/bin/ec

# Add a cosign wrapper command to handle "cosign initialize" for backwards
# compatibility with older task definitions
COPY --from=build /build/hack/fake-cosign.sh /usr/local/bin/cosign

ENTRYPOINT ["/usr/local/bin/ec"]
