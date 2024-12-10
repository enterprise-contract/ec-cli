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

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/registry"
)

func items(sourceImages []name.Reference, destination name.Registry) map[string]string {
	items := map[string]string{}
	for _, sourceImage := range sourceImages {
		var dest fmt.Stringer = destination.Repo(sourceImage.Context().RepositoryStr())
		if d, ok := sourceImage.(name.Digest); ok {
			dest = dest.(name.Repository).Digest(d.DigestStr())
		}
		if t, ok := sourceImage.(name.Tag); ok {
			dest = dest.(name.Repository).Tag(t.TagStr())
		}

		items[sourceImage.String()] = dest.String()
	}

	return items
}

func digestTag(ref name.Reference, suffix string) name.Reference {
	digest := ref.(name.Digest).DigestStr()

	tag := fmt.Sprintf("%s.%s", strings.Replace(digest, ":", "-", 1), suffix)

	return ref.Context().Tag(tag)
}

func signature(ref name.Reference) name.Reference {
	return digestTag(ref, "sig")
}

func attestation(ref name.Reference) name.Reference {
	return digestTag(ref, "att")
}

func sbom(ref name.Reference) name.Reference {
	return digestTag(ref, "sbom")
}

func referrers(ref name.Reference) ([]name.Reference, error) {
	var err error
	var idx v1.ImageIndex
	if d, ok := ref.(name.Digest); ok {
		idx, err = remote.Referrers(d)

		if err != nil {
			return nil, err
		}
	} else {
		img, err := remote.Image(ref)
		if err != nil {
			return nil, err
		}

		digest, err := img.Digest()
		if err != nil {
			return nil, err
		}
		ref := ref.Context().Digest(digest.String())
		idx, err = remote.Referrers(ref)
		if err != nil {
			return nil, err
		}
	}

	indexManifest, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}

	references := make([]name.Reference, 0, len(indexManifest.Manifests))
	for _, manifest := range indexManifest.Manifests {
		r := ref.Context().Digest(manifest.Digest.String())
		references = append(references, r)
	}

	return references, nil
}

func related(ref name.Reference) []name.Reference {
	references := []name.Reference{ref}

	for _, r := range []name.Reference{
		signature(ref),
		attestation(ref),
		sbom(ref),
	} {
		if _, err := remote.Image(r); err == nil {
			references = append(references, r)
		}
	}

	refs, err := referrers(ref)
	if err != nil {
		return references
	}

	return append(references, refs...)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <image> <directory>\n", os.Args[0])
		os.Exit(1)
	}

	sourceImage := os.Args[1]
	dir, err := filepath.Abs(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(3)
		}
	}

	source, err := name.ParseReference(sourceImage)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}

	_, ok := source.(name.Digest)
	if !ok {
		fmt.Fprintln(os.Stderr, "use pinned image references")
		os.Exit(5)
	}

	ctx := context.Background()
	registry, err := registry.Run(ctx,
		registry.DefaultImage,
		testcontainers.WithConfigModifier(func(config *container.Config) {
			config.User = fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
		}),
		testcontainers.WithHostConfigModifier(func(hostConfig *container.HostConfig) {
			hostConfig.UsernsMode = "host"
			hostConfig.Binds = append(hostConfig.Binds, fmt.Sprintf("%s:/var/lib/registry:z", dir))
		}),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(6)
	}
	defer func() { _ = registry.Terminate(ctx) }()

	destination, err := name.NewRegistry(registry.RegistryName, name.Insecure)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(7)
	}
	logs.Progress = log.New(os.Stdout, "", log.LstdFlags)

	sourceImages := related(source)

	idx, err := remote.Index(source)
	if err == nil {
		idxManifest, err := idx.IndexManifest()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(8)
		}

		for _, m := range idxManifest.Manifests {
			img := source.Context().Digest(m.Digest.String())
			sourceImages = append(sourceImages, related(img)...)
		}
	}

	for s, d := range items(sourceImages, destination) {
		if err := crane.Copy(s, d); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(9)
		}
	}
}
