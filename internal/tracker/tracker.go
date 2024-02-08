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
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	log "github.com/sirupsen/logrus"
	"github.com/stuart-warren/yamlfmt"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/yaml"

	"github.com/enterprise-contract/ec-cli/internal/image"
)

const taskCollection = "task-bundles"

type bundleRecord struct {
	Digest      string    `json:"digest"`
	EffectiveOn time.Time `json:"effective_on"`
	Tag         string    `json:"tag"`
	Repository  string    `json:"-"`
}

type Tracker struct {
	TaskBundles map[string][]bundleRecord `json:"task-bundles,omitempty"`
}

// newTracker returns a new initialized instance of Tracker. If path
// is "", an empty instance is returned.
func newTracker(input []byte) (t Tracker, err error) {
	if input != nil {
		err = yaml.Unmarshal(input, &t)
		if err != nil {
			return
		}
	} else {
		t = Tracker{}
	}

	t.setDefaults()
	return
}

// setDefaults initializes the required nested attributes.
func (t *Tracker) setDefaults() {
	if t.TaskBundles == nil {
		t.TaskBundles = map[string][]bundleRecord{}
	}
}

// addBundleRecord includes the given bundle record to the tracker.
func (t *Tracker) addBundleRecord(record bundleRecord) {
	collection := t.TaskBundles

	newRecords := []bundleRecord{record}
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
	return yamlfmt.Format(bytes.NewBuffer(out), true)
}

// Track implements the common workflow of loading an existing tracker file and adding
// records to one of its collections.
// Each url is expected to reference a valid Tekton bundle. Each bundle may be added
// to none, 1, or 2 collections depending on the Tekton resource types they include.
func Track(ctx context.Context, urls []string, input []byte, prune bool, freshen bool) ([]byte, error) {
	refs, err := image.ParseAndResolveAll(ctx, urls, name.StrictValidation)
	if err != nil {
		return nil, err
	}

	t, err := newTracker(input)
	if err != nil {
		return nil, err
	}

	if freshen {
		log.Debug("Freshen is enabled")
		imageRefs, err := inputBundleTags(ctx, t)
		if err != nil {
			return nil, err
		}

		refs = append(refs, imageRefs...)
	}

	effective_on := effectiveOn()
	for _, ref := range refs {
		log.Debugf("Processing bundle %q", ref.String())
		info, err := newBundleInfo(ctx, ref)
		if err != nil {
			return nil, err
		}

		for range sets.List(info.collections) {
			t.addBundleRecord(bundleRecord{
				Digest:      ref.Digest,
				Tag:         ref.Tag,
				EffectiveOn: effective_on,
				Repository:  ref.Repository,
			})
		}

	}

	t.filterBundles(prune)

	return t.Output()
}

func inputBundleTags(ctx context.Context, t Tracker) ([]image.ImageReference, error) {
	uniqueTagRefs := map[string]bool{}

	for repository, bundles := range t.TaskBundles {
		for _, bundle := range bundles {
			uniqueTagRefs[fmt.Sprintf("%s:%s", repository, bundle.Tag)] = true
		}
	}

	tagRefs := make([]string, 0, len(uniqueTagRefs))
	for bundle := range uniqueTagRefs {
		tagRefs = append(tagRefs, bundle)
	}

	return image.ParseAndResolveAll(ctx, tagRefs, name.StrictValidation)
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

// filterBundles applies filterRecords to TaskBundles.
func (t *Tracker) filterBundles(prune bool) {
	for ref, records := range t.TaskBundles {
		log.Debugf("Filtering task records for %q", ref)
		t.TaskBundles[ref] = filterRecords(records, prune)
	}
}

// filterRecords reduces the list of records by removing superfluous entries.
// It removes records that have the same Repository Digest, and Tag. If prune is
// true, it skips any record that is no longer acceptable. Any record with an
// EffectiveOn date in the future, and the record with the most recent
// EffectiveOn date *not* in the future are considered acceptable.
func filterRecords(records []bundleRecord, prune bool) []bundleRecord {
	now := time.Now().UTC()

	// lastDigestForTag tracks the latest digest seen for each tag.
	lastDigestForTag := map[string]string{}
	unique := make([]bundleRecord, 0, len(records))
	for i := len(records) - 1; i >= 0; i-- {
		// NOTE: Newly added records will have a repository, but existing ones
		// will not. This is expected because the output does not persist the
		// repository for each record. Instead, the repository is the attribute
		// which references the list of records.
		r := records[i]

		if digest, ok := lastDigestForTag[r.Tag]; ok && digest == r.Digest {
			continue
		}
		lastDigestForTag[r.Tag] = r.Digest

		unique = append([]bundleRecord{r}, unique...)
	}

	var relevant []bundleRecord
	if prune {
		// tagsToSkip tracks when records for a certain tag should start to be pruned.
		tagsToSkip := map[string]bool{}
		for _, r := range unique {
			if tagsToSkip[r.Tag] {
				continue
			}
			relevant = append(relevant, r)
			if !tagsToSkip[r.Tag] {
				if now.After(r.EffectiveOn) {
					tagsToSkip[r.Tag] = true
				}
			}
		}
	} else {
		relevant = unique
	}

	filteredCount := len(records) - len(relevant)
	if filteredCount != 0 {
		log.Debugf("Filtered %d records (prune=%t)", filteredCount, prune)
	}
	return relevant
}
