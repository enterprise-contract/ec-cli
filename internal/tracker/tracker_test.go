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

//go:build unit

package tracker

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"github.com/tektoncd/pipeline/pkg/remote/oci"
	"k8s.io/apimachinery/pkg/runtime"
)

var sampleHashOne = v1.Hash{
	Algorithm: "sha256",
	Hex:       "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
}

var sampleHashTwo = v1.Hash{
	Algorithm: "sha256",
	Hex:       "a2c1615816029636903a8172775682e8bbb84c6fde8d74b6de1e198f19f95c72",
}

var expectedEffectiveOn = effectiveOn().Format(time.RFC3339)

func TestTrack(t *testing.T) {
	tests := []struct {
		name   string
		urls   []string
		output string
		input  string
	}{
		{
			name: "always insert at the front",
			urls: []string{
				"registry.com/repo:two@" + sampleHashTwo.String(),
				"registry.com/repo:one@" + sampleHashOne.String(),
			},
			output: `---
pipeline-bundles:
  registry.com/repo:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: one
    - digest: ` + sampleHashTwo.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: two
required-tasks:
  - effective_on: "` + expectedEffectiveOn + `"
    tasks:
      - buildah
      - git-clone
      - summary
`,
		},
		{
			name: "multiple repos",
			urls: []string{
				"registry.com/one:1.0@" + sampleHashOne.String(),
				"registry.com/two:2.0@" + sampleHashTwo.String(),
			},
			output: `---
pipeline-bundles:
  registry.com/one:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "1.0"
  registry.com/two:
    - digest: ` + sampleHashTwo.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "2.0"
required-tasks:
  - effective_on: "` + expectedEffectiveOn + `"
    tasks:
      - buildah
      - git-clone
      - summary
`,
		},
		{
			name: "update existing repo",
			urls: []string{
				"registry.com/repo:two@" + sampleHashTwo.String(),
			},
			input: `---
pipeline-bundles:
  registry.com/repo:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: one
`,
			output: `---
pipeline-bundles:
  registry.com/repo:
    - digest: ` + sampleHashTwo.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: two
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: one
required-tasks:
  - effective_on: "` + expectedEffectiveOn + `"
    tasks:
      - buildah
      - git-clone
      - summary
`,
		},
		{
			name: "update existing collection",
			urls: []string{
				"registry.com/two:2.0@" + sampleHashTwo.String(),
			},
			input: `---
pipeline-bundles:
  registry.com/one:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "1.0"
`,
			output: `---
pipeline-bundles:
  registry.com/one:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "1.0"
  registry.com/two:
    - digest: ` + sampleHashTwo.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "2.0"
required-tasks:
  - effective_on: "` + expectedEffectiveOn + `"
    tasks:
      - buildah
      - git-clone
      - summary
`,
		},
		{
			name: "create new collection",
			urls: []string{
				"registry.com/two:2.0@" + sampleHashTwo.String(),
			},
			input: `task-bundles:
  registry.com/one:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "1.0"
`,
			output: `---
pipeline-bundles:
  registry.com/two:
    - digest: ` + sampleHashTwo.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "2.0"
required-tasks:
  - effective_on: "` + expectedEffectiveOn + `"
    tasks:
      - buildah
      - git-clone
      - summary
task-bundles:
  registry.com/one:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "1.0"
`,
		},
		{
			name: "mixed tasks and pipelines",
			urls: []string{
				"registry.com/mixed:1.0@" + sampleHashOne.String(),
			},
			output: `---
pipeline-bundles:
  registry.com/mixed:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "1.0"
required-tasks:
  - effective_on: "` + expectedEffectiveOn + `"
    tasks:
      - buildah
      - git-clone
      - summary
task-bundles:
  registry.com/mixed:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "1.0"
`,
		},
		{
			name: "pipeline without tasks",
			urls: []string{
				"registry.com/empty-pipeline:1.0@" + sampleHashOne.String(),
			},
			output: `---
pipeline-bundles:
  registry.com/empty-pipeline:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "1.0"
required-tasks:
  - effective_on: "` + expectedEffectiveOn + `"
    tasks: []
`,
		},
		{
			name: "pipeline without tasks and pipeline with tasks",
			urls: []string{
				"registry.com/empty-pipeline:1.0@" + sampleHashOne.String(),
				"registry.com/one:1.0@" + sampleHashOne.String(),
			},
			output: `---
pipeline-bundles:
  registry.com/empty-pipeline:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "1.0"
  registry.com/one:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "1.0"
required-tasks:
  - effective_on: "` + expectedEffectiveOn + `"
    tasks:
      - buildah
      - git-clone
      - summary
`,
		},
		{
			name: "pipeline with tasks then pipeline without tasks",
			urls: []string{
				"registry.com/one:1.0@" + sampleHashOne.String(),
				"registry.com/empty-pipeline:1.0@" + sampleHashOne.String(),
			},
			output: `---
pipeline-bundles:
  registry.com/empty-pipeline:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "1.0"
  registry.com/one:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "1.0"
required-tasks:
  - effective_on: "` + expectedEffectiveOn + `"
    tasks:
      - buildah
      - git-clone
      - summary
`,
		},
		{
			name: "required tasks removed",
			urls: []string{
				"registry.com/empty-pipeline:1.0@" + sampleHashOne.String(),
			},
			input: `required-tasks:
  - effective_on: "` + expectedEffectiveOn + `"
    tasks:
      - buildah
      - git-clone
      - summary
`,
			output: `---
pipeline-bundles:
  registry.com/empty-pipeline:
    - digest: ` + sampleHashOne.String() + `
      effective_on: "` + expectedEffectiveOn + `"
      tag: "1.0"
required-tasks:
  - effective_on: "` + expectedEffectiveOn + `"
    tasks: []
  - effective_on: "` + expectedEffectiveOn + `"
    tasks:
      - buildah
      - git-clone
      - summary
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			fs := afero.NewMemMapFs()
			inputFile := ""
			if tt.input != "" {
				err := afero.WriteFile(fs, "input.yaml", []byte(tt.input), 0444)
				assert.NoError(t, err)
				inputFile = "input.yaml"
			}

			client := fakeClient{objects: testObjects, images: testImages}
			ctx = WithClient(ctx, client)

			output, err := Track(ctx, fs, tt.urls, inputFile)
			assert.NoError(t, err)
			assert.Equal(t, tt.output, string(output))
		})
	}

}

type fakeClient struct {
	objects map[string]map[string]map[string]runtime.Object
	images  map[string]v1.Image
}

func (r fakeClient) GetTektonObject(ctx context.Context, bundle, kind, name string) (runtime.Object, error) {
	if bundle, ok := r.objects[bundle]; ok {
		if names, ok := bundle[kind]; ok {
			if obj, ok := names[name]; ok {
				return obj, nil
			}
		}
	}
	return nil, fmt.Errorf("resource named %q of kind %q not found", name, kind)
}

func (r fakeClient) GetImage(ctx context.Context, ref name.Reference) (v1.Image, error) {
	if image, ok := r.images[ref.String()]; ok {
		return image, nil
	}
	return nil, fmt.Errorf("image %q not found", ref)
}

var testObjects = map[string]map[string]map[string]runtime.Object{
	"registry.com/one:1.0@" + sampleHashOne.String(): {
		"pipeline": {
			"pipeline-v1": mustCreateFakePipelineObject(),
		},
	},
	"registry.com/two:2.0@" + sampleHashTwo.String(): {
		"pipeline": {
			"pipeline-v2": mustCreateFakePipelineObject(),
		},
	},
	"registry.com/repo:one@" + sampleHashOne.String(): {
		"pipeline": {
			"pipeline-v1": mustCreateFakePipelineObject(),
		},
	},
	"registry.com/repo:two@" + sampleHashTwo.String(): {
		"pipeline": {
			"pipeline-v2": mustCreateFakePipelineObject(),
		},
	},
	"registry.com/mixed:1.0@" + sampleHashOne.String(): {
		"pipeline": {
			"pipeline-v1": mustCreateFakePipelineObject(),
		},
	},
	"registry.com/empty-pipeline:1.0@" + sampleHashOne.String(): {
		"pipeline": {
			"pipeline-v1": mustCreateFakeEmptyPipelineObject(),
		},
	},
}

var testImages = map[string]v1.Image{
	"registry.com/one:1.0@" + sampleHashOne.String(): mustCreateFakeBundleImage([]fakeDefinition{
		{name: "pipeline-v1", kind: "pipeline"},
		// {name: "task-v1", kind: "task"},
	}),
	"registry.com/two:2.0@" + sampleHashTwo.String(): mustCreateFakeBundleImage([]fakeDefinition{
		{name: "pipeline-v2", kind: "pipeline"},
	}),
	"registry.com/repo:one@" + sampleHashOne.String(): mustCreateFakeBundleImage([]fakeDefinition{
		{name: "pipeline-v1", kind: "pipeline"},
		// {name: "task-v1", kind: "task"},
	}),
	"registry.com/repo:two@" + sampleHashTwo.String(): mustCreateFakeBundleImage([]fakeDefinition{
		{name: "pipeline-v2", kind: "pipeline"},
	}),
	"registry.com/mixed:1.0@" + sampleHashOne.String(): mustCreateFakeBundleImage([]fakeDefinition{
		{name: "pipeline-v1", kind: "pipeline"},
		{name: "task-v1", kind: "task"},
	}),
	"registry.com/empty-pipeline:1.0@" + sampleHashOne.String(): mustCreateFakeBundleImage([]fakeDefinition{
		{name: "pipeline-v1", kind: "pipeline"},
	}),
}

type fakeDefinition struct {
	name string
	kind string
}

func mustCreateFakeBundleImage(defs []fakeDefinition) v1.Image {
	adds := make([]mutate.Addendum, 0, len(defs))

	for _, definition := range defs {
		l, err := random.Layer(0, types.DockerLayer)
		if err != nil {
			panic("unable to create layer for test data")
		}
		adds = append(adds, mutate.Addendum{
			Layer: l,
			Annotations: map[string]string{
				oci.KindAnnotation:  definition.kind,
				oci.TitleAnnotation: definition.name,
			},
		})
	}

	img, err := mutate.Append(empty.Image, adds...)
	if err != nil {
		panic(err)
	}
	return img
}

func mustCreateFakePipelineObject() runtime.Object {
	gitCloneTask := v1beta1.PipelineTask{
		TaskRef: &v1beta1.TaskRef{
			Name: "git-clone",
		},
	}
	buildahTask := v1beta1.PipelineTask{
		TaskRef: &v1beta1.TaskRef{
			ResolverRef: v1beta1.ResolverRef{
				Resolver: "bundle",
				Params: []v1beta1.Param{
					{
						Name: "name",
						Value: v1beta1.ParamValue{
							StringVal: "buildah",
						},
					},
				},
			},
		},
	}
	summaryTask := v1beta1.PipelineTask{
		TaskRef: &v1beta1.TaskRef{
			Name: "summary",
		},
	}
	pipeline := v1beta1.Pipeline{}
	pipeline.SetDefaults(context.Background())
	pipeline.Spec.Tasks = []v1beta1.PipelineTask{gitCloneTask, buildahTask}
	pipeline.Spec.Finally = []v1beta1.PipelineTask{summaryTask}

	return &pipeline
}

func mustCreateFakeEmptyPipelineObject() runtime.Object {
	pipeline := v1beta1.Pipeline{}
	pipeline.SetDefaults(context.Background())
	return &pipeline
}

func TestDeduplicate(t *testing.T) {
	date, err := time.Parse(time.RFC3339, "2022-12-31T00:00:00Z")
	assert.NoError(t, err)

	repository := "registry.io/repository/image"

	existing := Tracker{
		PipelineBundles: map[string][]bundleRecord{
			repository: {
				{
					Repository:  repository,
					Tag:         "tag0",
					Digest:      "sha256:digest0",
					EffectiveOn: date,
					Collection:  pipelineCollection,
				},
				{
					Repository:  repository,
					Tag:         "tag1",
					Digest:      "sha256:digest1",
					EffectiveOn: date,
					Collection:  pipelineCollection,
				},
				{
					Repository:  repository,
					Tag:         "tag2",
					Digest:      "sha256:digest0",
					EffectiveOn: date,
					Collection:  pipelineCollection,
				},
				{
					Repository:  repository,
					Tag:         "tag3",
					Digest:      "sha256:digest0",
					EffectiveOn: date,
					Collection:  pipelineCollection,
				},
			},
		},
		TaskBundles: map[string][]bundleRecord{
			repository: {
				{
					Repository:  repository,
					Tag:         "tag0",
					Digest:      "sha256:digest0",
					EffectiveOn: date,
					Collection:  taskCollection,
				},
				{
					Repository:  repository,
					Tag:         "tag1",
					Digest:      "sha256:digest1",
					EffectiveOn: date,
					Collection:  taskCollection,
				},
				{
					Repository:  repository,
					Tag:         "tag2",
					Digest:      "sha256:digest0",
					EffectiveOn: date,
					Collection:  taskCollection,
				},
				{
					Repository:  repository,
					Tag:         "tag3",
					Digest:      "sha256:digest0",
					EffectiveOn: date,
					Collection:  taskCollection,
				},
			},
		},
	}

	existing.addBundleRecord(bundleRecord{
		Repository:  repository,
		Tag:         "tag4",
		Digest:      "sha256:digest1",
		EffectiveOn: date,
		Collection:  pipelineCollection,
	})

	existing.deduplicate()

	expected := Tracker{
		PipelineBundles: map[string][]bundleRecord{
			"registry.io/repository/image": {
				{
					Repository:  repository,
					Tag:         "tag4",
					Digest:      "sha256:digest1",
					EffectiveOn: date,
					Collection:  pipelineCollection,
				},
				{
					Repository:  repository,
					Tag:         "tag0",
					Digest:      "sha256:digest0",
					EffectiveOn: date,
					Collection:  pipelineCollection,
				},
			},
		},
		TaskBundles: map[string][]bundleRecord{
			"registry.io/repository/image": {
				{
					Repository:  repository,
					Tag:         "tag0",
					Digest:      "sha256:digest0",
					EffectiveOn: date,
					Collection:  taskCollection,
				},
				{
					Repository:  repository,
					Tag:         "tag1",
					Digest:      "sha256:digest1",
					EffectiveOn: date,
					Collection:  taskCollection,
				},
			},
		},
	}

	assert.Equal(t, expected, existing)
}
