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

package replacer

import (
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	log "github.com/sirupsen/logrus"

	"github.com/hacbs-contract/ec-cli/internal/image"
)

// imageReplacer defines the interface for finding and replacing image
// references included in a []byte, usually representing a file line.
type imageReplacer interface {
	match([]byte) bool
	replace([]byte) []byte
}

// basicImageReplacer implements the imageReplacer interface. It is
// responsible for replacing a static image reference.
type basicImageReplacer struct {
	*image.ImageReference
	regex *regexp.Regexp
}

// match returns true if the given line contains a matching image reference.
func (r *basicImageReplacer) match(line []byte) bool {
	return r.regex.Match(line)
}

// replace returns a new line with the matching image reference replaced.
func (r *basicImageReplacer) replace(line []byte) []byte {
	return r.regex.ReplaceAll(line, []byte(r.String()))
}

// newBasicImageReplacer returns a new instance of basicImageReplacer
// from a given ImageReference.
func newBasicImageReplacer(ref image.ImageReference) (*basicImageReplacer, error) {
	regex, err := regexp.Compile(regexp.QuoteMeta(ref.Repository) + `(:|@)\S+`)
	if err != nil {
		return nil, err
	}
	return &basicImageReplacer{&ref, regex}, nil
}

// catalogImageReplacer implements the imageReplacer interface. It is
// responsible for replacing image references based on the data of a
// catalog in Tekton Hub.
type catalogImageReplacer struct {
	client hubClient
	name   string
	regex  *regexp.Regexp
}

// match returns true if the given line contains an image reference that
// corresponds to the Tekton catalog.
func (r *catalogImageReplacer) match(line []byte) bool {
	return r.regex.Match(line)
}

// imageParseAndResolve makes it easier to write hermetic unit tests.
var imageParseAndResolve = image.ParseAndResolve

// replace returns a new line where any catalog image references are modified
// to use a new image reference with the latest version of the resource.
// Any sort of erros related to image reference parsing or digest resolution
// are logged as a warning, and the line is returned unmodified.
func (r *catalogImageReplacer) replace(line []byte) []byte {
	match := string(r.regex.Find(line))

	sourceRef, err := image.NewImageReference(match, name.StrictValidation)
	if err != nil {
		log.Warnf("unable to parse and resolve source ref: %s", err)
		return line
	}

	repository := sourceRef.Repository
	repositoryParts := strings.Split(repository, "/")
	name := repositoryParts[len(repositoryParts)-1]

	latestVersion, err := r.client.latestVersion(name, "task", r.name)
	if err != nil {
		log.Warnf("unable to fetch latest version for task %s: %s", name, err)
		return line
	}

	latestRef, err := imageParseAndResolve(repository + ":" + latestVersion)
	if err != nil {
		log.Warnf("unable to parse and resolve latest ref: %s", err)
		return line
	}
	return r.regex.ReplaceAll(line, []byte(latestRef.String()))
}

// newCatalogImageReplacer returns a new instance of catalogImageReplacer from
// the given CatalogOptions.
func newCatalogImageReplacer(opts *CatalogOptions) (*catalogImageReplacer, error) {
	// OCIRegex:    regexp.MustCompile(`registry.com/bundles/\S+`),
	regex, err := regexp.Compile(regexp.QuoteMeta(opts.RepoBase) + `\S+`)
	if err != nil {
		return nil, err
	}
	return &catalogImageReplacer{
		client: hubClient{url: opts.HubAPIURL},
		name:   opts.CatalogName,
		regex:  regex,
	}, nil
}
