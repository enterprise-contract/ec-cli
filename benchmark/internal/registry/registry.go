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

package registry

import (
	"context"

	"github.com/testcontainers/testcontainers-go/modules/registry"
)

type Closer interface {
	Close()
}

type registryCloser struct {
	container *registry.RegistryContainer
}

func (r *registryCloser) Close() {
	if r == nil || r.container == nil {
		return
	}

	_ = r.container.Terminate(context.Background())
}

func Launch(data string) (string, Closer, error) {
	ctx := context.Background()
	r, err := registry.Run(ctx, "registry:2.8.3", registry.WithData(data))
	c := &registryCloser{r}
	if err != nil {
		return "", c, err
	}

	return r.RegistryName, c, nil
}
