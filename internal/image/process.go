// Copyright 2022 Red Hat, Inc.
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

package image

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-multierror"
)

// ParseAndResolve parses the url into an ImageReference object. The digest is
// resolved if needed.
func ParseAndResolve(url string, opts ...name.Option) (*ImageReference, error) {
	ref, err := NewImageReference(url, opts...)
	if err != nil {
		return nil, err
	}

	if ref.Digest == "" {
		ref, err = ref.resolveDigest(opts...)
		if err != nil {
			return nil, err
		}
	}

	return ref, nil
}

// ParseAndResolveAll is like ParseAndResolve, but for a list of urls.
func ParseAndResolveAll(urls []string, opts ...name.Option) ([]ImageReference, error) {
	var errs error

	refs := make([]ImageReference, 0, len(urls))
	for _, url := range urls {
		ref, err := ParseAndResolve(url, opts...)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		refs = append(refs, *ref)
	}
	if errs != nil {
		return nil, errs
	}

	return refs, nil
}

type ImageReference struct {
	Repository string
	Digest     string
	Tag        string
	ref        name.Reference
}

// This facilitates unit tests.
var remoteHead = remote.Head

// resolveDigest queries the image repository to determine the image digest and
// returns a new instance of ImageReference with the updated digest value.
func (i ImageReference) resolveDigest(opts ...name.Option) (*ImageReference, error) {
	descriptor, err := remoteHead(i.ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, err
	}
	digest := descriptor.Digest.String()
	if digest == "" {
		return nil, fmt.Errorf("digest for image %q is empty", i.ref.String())
	}

	return NewImageReference(fmt.Sprintf("%s:%s@%s", i.Repository, i.Tag, digest), opts...)
}

func (i *ImageReference) String() string {
	// An image reference has at most 3 parts (repo, tag, digest) plus 2 separators
	parts := make([]string, 0, 5)
	parts = append(parts, i.Repository)
	if i.Tag != "" {
		parts = append(parts, ":", i.Tag)
	}
	if i.Digest != "" {
		parts = append(parts, "@", i.Digest)
	}
	return strings.Join(parts, "")
}

// NewImageReference returns an ImageReference instance based on the given url.
func NewImageReference(url string, opts ...name.Option) (*ImageReference, error) {
	ref, err := name.ParseReference(url, opts...)
	if err != nil {
		return nil, err
	}
	imageRef := &ImageReference{ref: ref}

	// An image reference may contain both a tag and a digest. However, the parsing library
	// will drop the tag in favor of the digest. Since we care about the value of the tag,
	// parse the url without the digest reference to force the library to retain the tag
	// value in all cases where it is present.
	tagRef, err := name.NewTag(strings.Split(url, "@")[0], opts...)
	if err == nil {
		imageRef.Tag = tagRef.TagStr()
		imageRef.Repository = tagRef.Context().Name()
	}

	digestRef, err := name.NewDigest(url, opts...)
	if err == nil {
		imageRef.Digest = digestRef.DigestStr()
		imageRef.Repository = digestRef.Context().Name()
	}

	return imageRef, nil
}

func (i ImageReference) Ref() name.Reference {
	return i.ref
}
