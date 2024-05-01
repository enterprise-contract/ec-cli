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

set -o errexit
set -o nounset
set -o pipefail

AUTO_TAG=$(hack/derive-version.sh)

if [ -z "$(git tag -l $AUTO_TAG)" ]; then
  # Create a tag
  echo "Creating tag $AUTO_TAG"
  git tag -a -m 'Version tag added automatically after snapshot build.' "$AUTO_TAG"

else
  # The tag exists already
  # Hopefully this won't happen, but let's not break the build if it does
  THIS_SHA=$(git rev-list -n1 --abbrev-commit HEAD)
  TAG_SHA=$(git rev-list -n1 --abbrev-commit "$AUTO_TAG")

  if [ "$TAG_SHA" = "$THIS_SHA" ]; then
    # Tag is already what we wanted it to be. No big deal.
    echo "Tag $AUTO_TAG exists already"

  else
    # This is more surprising. If you see this it's likely you want to do
    # some debugging to figure out what happened and why
    echo "Tag $AUTO_TAG exists already but on $TAG_SHA not $THIS_SHA. Skipping tag creation."
    echo "You should try to figure out why this happened!"

    # Todo: Once we think this is stable enough we should fail more loudly
    #exit 1

  fi
fi
