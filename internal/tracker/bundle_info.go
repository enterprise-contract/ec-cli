// Copyright The Enterprise Contract Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package tracker

import (
	"context"

	"github.com/tektoncd/pipeline/pkg/remote/oci"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/enterprise-contract/ec-cli/internal/image"
)

type bundleInfo struct {
	ref         image.ImageReference
	collections sets.Set[string] // Set of collection where the bundle should be tracked under.
}

// newBundleInfo returns information about the bundle, such as which collections it should
// be added to.
func newBundleInfo(ctx context.Context, ref image.ImageReference) (*bundleInfo, error) {
	info := bundleInfo{ref: ref, collections: sets.New[string]()}

	client := NewClient(ctx)
	img, err := client.GetImage(ctx, info.ref.Ref())
	if err != nil {
		return nil, err
	}

	manifest, err := img.Manifest()
	if err != nil {
		return nil, err
	}

	for _, layer := range manifest.Layers {
		if kind, ok := layer.Annotations[oci.KindAnnotation]; ok {
			switch kind {
			case "task":
				info.collections.Insert(taskCollection)
			}
		}
	}

	return &info, nil
}
