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

package tracker

import (
	"bytes"
	"context"
	"io/ioutil"
	"time"

	"github.com/ghodss/yaml"
	"github.com/stuart-warren/yamlfmt"

	"github.com/hacbs-contract/ec-cli/internal/image"
)

type Record struct {
	Digest      string    `json:"digest"`
	EffectiveOn time.Time `json:"effective_on"`
	Tag         string    `json:"tag"`
	Repository  string    `json:"-"`
	Collection  string    `json:"-"`
}

type Tracker map[string]map[string][]Record

type Collector func(context.Context, image.ImageReference) ([]string, error)

// newTracker returns a new initialized instance of Tracker. If path
// is "", an empty instance is returned.
func newTracker(path string) (t Tracker, err error) {
	if path != "" {
		var contents []byte
		contents, err = ioutil.ReadFile(path)
		if err != nil {
			return
		}
		err = yaml.Unmarshal(contents, &t)
		if err != nil {
			return
		}
	} else {
		t = Tracker{}
	}
	return
}

// add includes the given record to the tracker.
func (t Tracker) add(record Record) {
	if _, ok := t[record.Collection]; !ok {
		t[record.Collection] = map[string][]Record{}
	}
	collection := t[record.Collection]

	newRecords := []Record{record}
	if _, ok := collection[record.Repository]; !ok {
		collection[record.Repository] = newRecords
	} else {
		collection[record.Repository] = append(newRecords, collection[record.Repository]...)
	}
}

// Output serializes the Tracker state as YAML
func (t Tracker) Output() ([]byte, error) {
	out, err := yaml.Marshal(t)
	if err != nil {
		return nil, err
	}

	// sorts the YAML document making it deterministic
	return yamlfmt.Format(bytes.NewBuffer(out))
}

// Track implements the common workflow of loading an existing tracker file and adding
// records to one of its collections.
func Track(ctx context.Context, urls []string, input string, collector Collector) ([]byte, error) {
	refs, err := image.ParseAndResolveAll(urls)
	if err != nil {
		return nil, err
	}

	t, err := newTracker(input)
	if err != nil {
		return nil, err
	}

	effective_on := effectiveOn()
	for _, ref := range refs {
		collections, err := collector(ctx, ref)
		if err != nil {
			return nil, err
		}

		for _, collection := range collections {
			t.add(Record{
				Digest:      ref.Digest,
				Tag:         ref.Tag,
				EffectiveOn: effective_on,
				Repository:  ref.Repository,
				Collection:  collection + "-bundles",
			})
		}
	}

	out, err := yaml.Marshal(t)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// effectiveOn returns an RFC3339 representation of the beginning of the
// closest day 30 days into the future. 30 is a best guess number. In the
// future, this may have to be configurable.
func effectiveOn() time.Time {
	day := time.Hour * 24
	duration := day * 30
	// Round to the 0 time of the day for consistency. Also, zero out nanoseconds
	// to avoid RFC3339Nano from being used by MarshalJSON.
	return time.Now().Add(duration).UTC().Round(day)
}
