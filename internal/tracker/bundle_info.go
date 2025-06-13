// Copyright The Conforma Contributors
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

	"github.com/conforma/cli/internal/image"
)

// containsTask returns if the bundle contains a Tekton Task
func containsTask(ctx context.Context, ref image.ImageReference) (bool, error) {
	client := NewClient(ctx)
	img, err := client.GetImage(ctx, ref.Ref())
	if err != nil {
		return false, err
	}

	manifest, err := img.Manifest()
	if err != nil {
		return false, err
	}

	for _, layer := range manifest.Layers {
		if kind, ok := layer.Annotations[oci.KindAnnotation]; ok {
			switch kind {
			case "task":
				return true, nil
			}
		}
	}

	return false, nil
}
