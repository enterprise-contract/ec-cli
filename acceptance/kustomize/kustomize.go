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

package kustomize

import (
	"path"

	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

var hackDir = "hack"

func Render(dir string) ([]byte, error) {
	options := krusty.MakeDefaultOptions()
	options.Reorder = krusty.ReorderOptionLegacy                                    // otherwise Namespace object might appear after an object that needs it
	options.PluginConfig = types.EnabledPluginConfig(types.BploUseStaticallyLinked) // enable plugins
	options.PluginConfig.FnpLoadingOptions.EnableExec = true                        // we allow KEP exec plugins

	kustomize := krusty.MakeKustomizer(options)
	result, err := kustomize.Run(filesys.MakeFsOnDisk(), path.Join(hackDir, dir))
	if err != nil {
		return nil, err
	}

	return result.AsYaml()
}
