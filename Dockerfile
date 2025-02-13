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

# -----------------------------------
# Stage 1: Build ec binaries
# -----------------------------------

FROM docker.io/library/golang:1.22.7 AS build

ARG TARGETOS
ARG TARGETARCH
ARG BUILD_SUFFIX=""
ARG BUILD_LIST="${TARGETOS}_${TARGETARCH}"

# Avoid safe directory git failures building with default user from go-toolset
USER root

WORKDIR /build

# Copy just the mod file for better layer caching when building locally
COPY go.mod go.sum ./
RUN go mod download

# Copy the tools/kubectl mod file for better layer caching when building locally
COPY tools/kubectl/go.mod tools/kubectl/go.sum ./tools/kubectl/
RUN cd tools/kubectl && go mod download

# Now copy everything including .git
COPY . .

RUN /build/build.sh "${BUILD_LIST}" "${BUILD_SUFFIX}"

# -----------------------------------
# Stage 2: Install extra packages
# -----------------------------------
FROM registry.access.redhat.com/ubi9/ubi:9.5@sha256:4495380286c97b9c2635b0b5d6f227bbd9003628be8383a37ff99984eefa42ed AS packages
# Create a directory for the rootfs then install packages into it. These will be copied
# into the final image. We do this so that there's a record of the installed packages for
# SBOM inspection.
RUN mkdir -p /mnt/rootfs
RUN \
    rpm --root=/mnt/rootfs --import /mnt/rootfs/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
RUN \
    dnf install --installroot /mnt/rootfs \
      jq gzip ca-certificates \
      --releasever 9 --setopt=install_weak_deps=false --nodocs \
      --setopt=reposdir=/etc/yum.repos.d/ -y && \
    dnf --installroot /mnt/rootfs clean all
RUN rm -rf /mnt/rootfs/var/cache/* /mnt/rootfs/var/log/dnf* /mnt/rootfs/var/log/yum.* /mnt/rootfs/usr/share/zoneinfo

# -----------------------------------
# Stage 3: Final image based on UBI-micro
# (It does NOT include microdnf, so we must copy in the tools.)
# -----------------------------------
FROM registry.access.redhat.com/ubi9/ubi-micro:9.5@sha256:4a2052ef4db4fd1a53b45263b5067eb01d5745fdd300b27986952af27887bc27
ARG TARGETOS
ARG TARGETARCH
ARG CLI_NAME="Conforma"

LABEL \
  name="ec-cli" \
  description="${CLI_NAME} verifies and checks supply chain artifacts to ensure they meet security and business policies." \
  io.k8s.description="${CLI_NAME} verifies and checks supply chain artifacts to ensure they meet security and business policies." \
  summary="Provides the binaries for downloading the ${CLI_NAME} CLI. Also used as a runner image for Tekton tasks." \
  io.k8s.display-name="${CLI_NAME}" \
  io.openshift.tags="conforma ec opa cosign sigstore"

# Copy in the packages from the 'packages' stage.
COPY --from=packages /mnt/rootfs/ /

# Copy all the binaries so they're available to extract and download
# (Beware if you're testing this locally it will copy everything from
# your dist directory, not just the freshly built binaries.)
COPY --from=build /build/dist/ec* /usr/local/bin/

# Gzip them because that's what the cli downloader image expects, see
# https://github.com/securesign/cosign/blob/main/Dockerfile.client-server-re.rh
RUN gzip /usr/local/bin/ec_*

# Copy the one ec binary that can run in this container
COPY --from=build "/build/dist/ec_${TARGETOS}_${TARGETARCH}" /usr/local/bin/ec

# Copy the one kubectl binary that can run in this container
COPY --from=build "/build/dist/kubectl_${TARGETOS}_${TARGETARCH}" /usr/local/bin/kubectl

# Copy reduce-snapshot script needed for single component mode
COPY hack/reduce-snapshot.sh /usr/local/bin

# OpenShift preflight check requires a license
COPY --from=build /build/LICENSE /licenses/LICENSE

# OpenShift preflight check requires a non-root user
USER 1001

# Show some version numbers for troubleshooting purposes
RUN jq --version && ec version && ls -l /usr/local/bin

ENTRYPOINT ["/usr/local/bin/ec"]
