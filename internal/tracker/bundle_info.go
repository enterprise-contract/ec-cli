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
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"github.com/tektoncd/pipeline/pkg/remote/oci"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/hacbs-contract/ec-cli/internal/image"
)

type bundleInfo struct {
	ref image.ImageReference
	// Set of common Tasks found across Pipelines definitions in the bundle.
	commonPipelineTasks commonTasksRecord
	// Set of collection where the bundle should be tracked under.
	collections   sets.Set[string]
	pipelineTasks map[string][]string
}

// newBundleInfo returns information about the bundle, such as which collections it should
// be added to, and which common tasks are found within its pipeline definitions.
func newBundleInfo(ctx context.Context, ref image.ImageReference, tasks commonTasksRecord) (*bundleInfo, error) {
	info := bundleInfo{ref: ref, collections: sets.New[string](), commonPipelineTasks: tasks}

	client := NewClient(ctx)
	img, err := client.GetImage(ctx, info.ref.Ref())
	if err != nil {
		return nil, err
	}

	manifest, err := img.Manifest()
	if err != nil {
		return nil, err
	}

	for _, layer := range manifest.Layers {
		if kind, ok := layer.Annotations[oci.KindAnnotation]; ok {
			if name, ok := layer.Annotations[oci.TitleAnnotation]; ok {
				switch kind {
				case "pipeline":
					info.collections.Insert(pipelineCollection)
					if err := info.updatePipelineTasks(ctx, name); err != nil {
						return nil, err
					}
				case "task":
					info.collections.Insert(taskCollection)
				}
			}
		}
	}

	return &info, nil
}

// getBundlePipeline gets a pipeline from a bundle by the pipeline name
func (info *bundleInfo) getBundlePipeline(ctx context.Context, pipelineName string) (error, v1beta1.PipelineObject) {
	client := NewClient(ctx)
	bundle := info.ref.String()
	runtimeObject, err := client.GetTektonObject(ctx, bundle, "pipeline", pipelineName)
	if err != nil {
		return err, nil
	}
	pipelineObject, ok := runtimeObject.(v1beta1.PipelineObject)
	if !ok {
		return fmt.Errorf("pipeline resource, %q, cannot be converted to a PipelineObject", pipelineName), nil
	}
	pipelineObject.SetDefaults(ctx)

	return nil, pipelineObject
}

// updateRequiredTasks updates the required common tasks and required pipeline tasks
func (info *bundleInfo) updatePipelineTasks(ctx context.Context, pipelineName string) error {
	err, pipelineObject := info.getBundlePipeline(ctx, pipelineName)
	if err != nil {
		return err
	}
	// Filter out unwanted pipelines
	// TODO: Consider making this filter configurable at some point in the future.
	if val, ok := pipelineObject.PipelineMetadata().Labels["skip-hacbs-test"]; ok && val == "true" {
		return nil
	}
	pipelineTaskNames := getTaskNames(pipelineObject.PipelineSpec())
	info.pipelineTasks = map[string][]string{
		pipelineObject.PipelineMetadata().Name: sets.List(pipelineTaskNames),
	}
	info.commonPipelineTasks.updateTasksIntersection(pipelineTaskNames)
	return nil
}

// getTaskNames returns a set of task names found in the pipeline spec.
func getTaskNames(pipelineSpec v1beta1.PipelineSpec) sets.Set[string] {
	names := sets.New[string]()
	tasks := append(pipelineSpec.Tasks, pipelineSpec.Finally...)
	for _, task := range tasks {
		name := getTaskName(task.TaskRef)
		if name != "" {
			names = names.Insert(name)
		}
	}
	return names
}

// getTaskName returns the name of the task in the TaskRef.
// If a name cannot be found, an empty string is returned.
func getTaskName(taskRef *v1beta1.TaskRef) string {
	if taskRef.Resolver != "" {
		for _, param := range taskRef.ResolverRef.Params {
			if param.Name == "name" {
				return param.Value.StringVal
			}
		}
		log.Warnf("Unable to retrieve resolver task name from TaskRef: %#v", taskRef)
		return ""
	}
	return taskRef.Name
}
