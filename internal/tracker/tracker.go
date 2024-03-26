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
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	log "github.com/sirupsen/logrus"
	"github.com/stuart-warren/yamlfmt"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/yaml"

	"github.com/enterprise-contract/ec-cli/internal/image"
)

const taskCollection = "task-bundles"
const ociPrefix = "oci://"

type taskRecord struct {
	Ref         string    `json:"ref"`
	EffectiveOn time.Time `json:"effective_on"`
	// ExpiresOn should be omitted if there isn't a value. Not using a pointer means it will always
	// have a value, e.g. 0001-01-01T00:00:00Z.
	ExpiresOn  *time.Time `json:"expires_on,omitempty"`
	Tag        string     `json:"-"`
	Repository string     `json:"-"`
}

type bundleRecord struct {
	Digest      string    `json:"digest"`
	EffectiveOn time.Time `json:"effective_on"`
	// ExpiresOn should be omitted if there isn't a value. Not using a pointer means it will always
	// have a value, e.g. 0001-01-01T00:00:00Z.
	ExpiresOn  *time.Time `json:"expires_on,omitempty"`
	Tag        string     `json:"tag"`
	Repository string     `json:"-"`
}

type Tracker struct {
	// TaskBundles is deprecated and will be removed in the future. Use TrustedTasks instead.
	TaskBundles  map[string][]bundleRecord `json:"task-bundles,omitempty"`
	TrustedTasks map[string][]taskRecord   `json:"trusted_tasks,omitempty"`
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
	if t.TrustedTasks == nil {
		t.TrustedTasks = map[string][]taskRecord{}
	}
	if t.TaskBundles == nil {
		t.TaskBundles = map[string][]bundleRecord{}
	}
}

// addTrustedTaskRecord includes the given Tekton bundle Task record in the tracker.
func (t *Tracker) addTrustedTaskRecord(prefix string, record taskRecord) {
	newRecords := []taskRecord{record}
	var group string
	if record.Tag == "" {
		group = fmt.Sprintf("%s%s", prefix, record.Repository)
	} else {
		group = fmt.Sprintf("%s%s:%s", prefix, record.Repository, record.Tag)
	}
	if _, ok := t.TrustedTasks[group]; !ok {
		t.TrustedTasks[group] = newRecords
	} else {
		t.TrustedTasks[group] = append(newRecords, t.TrustedTasks[group]...)
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
	t, err := newTracker(input)
	if err != nil {
		return nil, err
	}

	if len(t.TrustedTasks) == 0 && len(t.TaskBundles) > 0 {
		log.Debug("converting deprecated task-bundles format to trusted_tasks")
		for repo, bundles := range t.TaskBundles {
			for i := len(bundles) - 1; i >= 0; i-- {
				bundle := bundles[i]
				t.addTrustedTaskRecord(ociPrefix, taskRecord{
					Ref:         bundle.Digest,
					Tag:         bundle.Tag,
					EffectiveOn: bundle.EffectiveOn,
					ExpiresOn:   bundle.ExpiresOn,
					Repository:  repo,
				})
			}
		}
	}
	t.TaskBundles = map[string][]bundleRecord{}

	imageUrls, gitUrls := groupUrls(urls)

	if err := t.trackImageReferences(ctx, imageUrls, freshen); err != nil {
		return nil, err
	}

	if err := t.trackGitReferences(ctx, gitUrls); err != nil {
		return nil, err
	}

	t.filterBundles(prune)

	t.setExpiration()

	if err := t.convertToOldFormat(); err != nil {
		return nil, err
	}

	return t.Output()
}

func groupUrls(urls []string) ([]string, []string) {
	imgs := make([]string, 0, len(urls))
	gits := make([]string, 0, len(urls))
	for _, u := range urls {
		if strings.HasPrefix(u, "git+") {
			gits = append(gits, u)
		} else {
			imgs = append(imgs, u)
		}
	}

	return imgs, gits
}

func (t *Tracker) trackImageReferences(ctx context.Context, urls []string, freshen bool) error {
	refs, err := image.ParseAndResolveAll(ctx, urls, name.StrictValidation)
	if err != nil {
		return err
	}

	if freshen {
		log.Debug("Freshen is enabled")
		imageRefs, err := inputBundleTags(ctx, *t)
		if err != nil {
			return err
		}

		refs = append(refs, imageRefs...)
	}

	effective_on := effectiveOn()
	for _, ref := range refs {
		log.Debugf("Processing bundle %q", ref.String())
		info, err := newBundleInfo(ctx, ref)
		if err != nil {
			return err
		}

		for range sets.List(info.collections) {
			t.addTrustedTaskRecord(ociPrefix, taskRecord{
				Ref:         ref.Digest,
				Tag:         ref.Tag,
				EffectiveOn: effective_on,
				Repository:  ref.Repository,
			})
		}
	}

	return nil
}

func (t *Tracker) trackGitReferences(_ context.Context, urls []string) error {
	effective_on := effectiveOn()

	for _, u := range urls {
		repository, rest, found := strings.Cut(u, "//")
		if !found {
			return fmt.Errorf("expected %q to contain the `//` to separate the repository from the path, e.g. git+https://github.com/org/repository//task/0.1/task.yaml@f0cacc1a", u)
		}
		path, rev, found := strings.Cut(rest, "@")
		if !found {
			return fmt.Errorf("expected %q to contain the `@` to separate the path from the revision, e.g. git+https://github.com/org/repository//task/0.1/task.yaml@f0cacc1a", u)
		}

		t.addTrustedTaskRecord("", taskRecord{
			Repository:  fmt.Sprintf("%s//%s", repository, path),
			Ref:         rev,
			EffectiveOn: effective_on,
		})
	}

	return nil
}

func inputBundleTags(ctx context.Context, t Tracker) ([]image.ImageReference, error) {
	uniqueTagRefs := map[string]bool{}

	for group := range t.TrustedTasks {
		tagRef := ociRefFromGroup(group)
		if tagRef == "" {
			// Not an OCI bundle
			continue
		}
		uniqueTagRefs[tagRef] = true
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
	for group, records := range t.TrustedTasks {
		log.Debugf("Filtering task records for %q", group)
		t.TrustedTasks[group] = filterRecords(records, prune)
	}
}

// filterRecords reduces the list of records by removing superfluous entries.
// It removes records that have the same reference in a certain group. If prune is
// true, it skips any record that is no longer acceptable. Any record with an
// EffectiveOn date in the future, and the record with the most recent
// EffectiveOn date *not* in the future are considered acceptable.
func filterRecords(records []taskRecord, prune bool) []taskRecord {
	now := time.Now().UTC()

	// lastRef tracks the latest ref seen. This is used to remove consecutive entries with the
	// same digest.
	var lastRef string
	unique := make([]taskRecord, 0, len(records))
	for i := len(records) - 1; i >= 0; i-- {
		// NOTE: Newly added records will have a repository, but existing ones
		// will not. This is expected because the output does not persist the
		// repository for each record. Instead, the repository is the attribute
		// which references the list of records.
		r := records[i]

		if lastRef == r.Ref {
			continue
		}
		lastRef = r.Ref

		unique = append([]taskRecord{r}, unique...)
	}

	var relevant []taskRecord
	if prune {
		// skip tracks when records should start to be pruned.
		skip := false
		for _, r := range unique {
			if skip {
				continue
			}
			relevant = append(relevant, r)
			if !skip {
				if now.After(r.EffectiveOn) {
					skip = true
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

// setExpiration sets the expires_on attribute on records. The expires_on value for record N is the
// effective_on value of the n-1 record. The first record on the list does not contain an expires_on
// value since there is no newer record that invalidates it in the future.
// TODO: Probably need to compute the expires_on value without requiring the "effective_on" value so
// we don't have to always require both values. But this may be required during some transition
// period.
func (t *Tracker) setExpiration() {
	for _, records := range t.TrustedTasks {
		var expiration *time.Time
		for i := range records {
			if expiration != nil {
				records[i].ExpiresOn = expiration
			}
			expiration = &records[i].EffectiveOn
		}
	}
}

func (t *Tracker) convertToOldFormat() error {
	for group, tasks := range t.TrustedTasks {
		repo := ociRefFromGroup(group)
		if repo == "" {
			// Not an OCI group
			continue
		}
		for _, task := range tasks {
			ref, err := name.NewTag(repo)
			if err != nil {
				return fmt.Errorf("cannot parse existing repo as a tag ref: %w", err)
			}
			t.addBundleRecord(bundleRecord{
				Digest:      task.Ref,
				Tag:         ref.TagStr(),
				Repository:  ref.Repository.Name(),
				EffectiveOn: task.EffectiveOn,
				ExpiresOn:   task.ExpiresOn,
			})
		}
	}

	for _, bundles := range t.TaskBundles {
		// Sort the task bundles in reverse order. The first bundle being the most recent one. The
		// sorting function returns true if the bundle at "i" is considered newer than the bundle at
		// "j". It is assumed that every bundle has an EffectiveOn date and a Tag, but some bundles
		// may not have an ExpiresOn date.
		sort.SliceStable(bundles, func(i, j int) bool {
			if !bundles[i].EffectiveOn.Equal(bundles[j].EffectiveOn) {
				return bundles[i].EffectiveOn.After(bundles[j].EffectiveOn)
			}

			iExpiresOn := bundles[i].ExpiresOn
			jExpiresOn := bundles[j].ExpiresOn
			// A missing ExpiresOn value is always considered to be newer than an explicit value.
			// Only one defines an expiration date. "i" is newer if it is the one that is null.
			if (iExpiresOn == nil || jExpiresOn == nil) && iExpiresOn != jExpiresOn {
				return iExpiresOn == nil
			}
			if iExpiresOn != nil && jExpiresOn != nil && !iExpiresOn.Equal(*jExpiresOn) {
				return iExpiresOn.After(*jExpiresOn)
			}

			// Records are pretty similar. Use the tag as a tie breaker to produce a stable order.
			return bundles[i].Tag > bundles[j].Tag
		})
	}

	return nil
}

// ociRefFromGroup returns the OCI image reference from the given group, e.g.
// oci://registry.local/spam:latest -> registry.local/spam:latest
// If the group does not represent an OCI image reference, an empty string is returned.
func ociRefFromGroup(group string) string {
	if !strings.HasPrefix(group, ociPrefix) {
		// Not an OCI bundle
		return ""
	}
	return strings.TrimPrefix(group, ociPrefix)
}
