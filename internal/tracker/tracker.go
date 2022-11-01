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
	"time"

	"github.com/ghodss/yaml"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/stuart-warren/yamlfmt"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/hacbs-contract/ec-cli/internal/image"
)

const (
	pipelineCollection = "pipeline-bundles"
	taskCollection     = "task-bundles"
)

type bundleRecord struct {
	Digest      string    `json:"digest"`
	EffectiveOn time.Time `json:"effective_on"`
	Tag         string    `json:"tag"`
	Repository  string    `json:"-"`
	Collection  string    `json:"-"`
}

type commonTasksRecord struct {
	Tasks       []string  `json:"tasks"`
	EffectiveOn time.Time `json:"effective_on"`
}

func (r *commonTasksRecord) updateTasksIntersection(newTasks sets.String) {
	if len(r.Tasks) == 0 {
		r.Tasks = newTasks.List()
	} else if newTasks.Len() > 0 {
		existingTasks := sets.NewString(r.Tasks...)
		r.Tasks = existingTasks.Intersection(newTasks).List()
	}
}

type Tracker struct {
	PipelineBundles map[string][]bundleRecord `json:"pipeline-bundles,omitempty"`
	TaskBundles     map[string][]bundleRecord `json:"task-bundles,omitempty"`
	RequiredTasks   []commonTasksRecord       `json:"required-tasks,omitempty"`
}

// newTracker returns a new initialized instance of Tracker. If path
// is "", an empty instance is returned.
func newTracker(fs afero.Fs, path string) (t Tracker, err error) {
	if path != "" {
		var contents []byte
		contents, err = afero.ReadFile(fs, path)
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

	t.setDefaults()
	return
}

// setDefaults initializes the required nested attributes.
func (t *Tracker) setDefaults() {
	if t.PipelineBundles == nil {
		t.PipelineBundles = map[string][]bundleRecord{}
	}
	if t.TaskBundles == nil {
		t.TaskBundles = map[string][]bundleRecord{}
	}
}

// addBundleRecord includes the given bundle record to the tracker.
func (t *Tracker) addBundleRecord(record bundleRecord) {
	var collection map[string][]bundleRecord
	switch record.Collection {
	case pipelineCollection:
		collection = t.PipelineBundles
	case taskCollection:
		collection = t.TaskBundles
	default:
		log.Warnf("Ignoring record with unexpected collection: %#v", record)
		return
	}

	newRecords := []bundleRecord{record}
	if _, ok := collection[record.Repository]; !ok {
		collection[record.Repository] = newRecords
	} else {
		collection[record.Repository] = append(newRecords, collection[record.Repository]...)
	}
}

// addRequiredTasksRecord includes the given tasks record to the tracker as required tasks.
// If the most recent entry contains the same set of tasks, no action is taken.
func (t *Tracker) addRequiredTasksRecord(record commonTasksRecord) {
	if len(t.RequiredTasks) > 0 {
		existingTasks := sets.NewString(t.RequiredTasks[0].Tasks...)
		if existingTasks.Equal(sets.NewString(record.Tasks...)) {
			return
		}
	}
	t.RequiredTasks = append([]commonTasksRecord{record}, t.RequiredTasks...)
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
// Each url is expected to reference a valid Tekton bundle. Each bundle may be added
// to none, 1, or 2 collections depending on the Tekton resource types they include.
func Track(ctx context.Context, fs afero.Fs, urls []string, input string) ([]byte, error) {
	refs, err := image.ParseAndResolveAll(urls)
	if err != nil {
		return nil, err
	}

	t, err := newTracker(fs, input)
	if err != nil {
		return nil, err
	}

	effective_on := effectiveOn()
	requiredTasks := commonTasksRecord{EffectiveOn: effective_on}
	for _, ref := range refs {
		info, err := newBundleInfo(ctx, ref, requiredTasks)
		if err != nil {
			return nil, err
		}

		for _, collection := range info.collections.List() {
			t.addBundleRecord(bundleRecord{
				Digest:      ref.Digest,
				Tag:         ref.Tag,
				EffectiveOn: effective_on,
				Repository:  ref.Repository,
				Collection:  collection,
			})
		}
		requiredTasks = info.commonPipelineTasks

	}
	t.addRequiredTasksRecord(requiredTasks)

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
