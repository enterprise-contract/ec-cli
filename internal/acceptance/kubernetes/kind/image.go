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

package kind

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
)

func (k *kindCluster) buildCliImage(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "make", "--no-print-directory", "-C", path.Join("..", ".."), "push-image", fmt.Sprintf("IMAGE_REPO=localhost:%d/ec-cli", k.registryPort), "PODMAN_OPTS=--tls-verify=false")

	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Print(string(out))
		return err
	}

	return nil
}

func (k *kindCluster) buildTaskBundleImage(ctx context.Context) error {
	versions, err := filepath.Glob(path.Join("..", "..", "task", "*.*"))
	if err != nil {
		return err
	}

	for _, version := range versions {
		if info, err := os.Stat(version); err != nil {
			return err
		} else if !info.IsDir() {
			continue
		}

		taskFile := path.Join(version, "verify-enterprise-contract.yaml")

		if info, err := os.Stat(taskFile); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}

			return err
		} else if info.IsDir() {
			continue
		}

		var bytes []byte
		if bytes, err = os.ReadFile(taskFile); err != nil {
			return err
		}

		var taskDefinition v1beta1.Task
		if err := yaml.Unmarshal(bytes, &taskDefinition); err != nil {
			return err
		}

		// using registry.image-registry.svc.cluster.local instead of 127.0.0.1
		// leads to "dial tcp: lookup registry.image-registry.svc.cluster.local:
		// Temporary failure in name resolution" in Tekton Pipeline controller
		img := fmt.Sprintf("127.0.0.1:%d/ec-cli:latest-%s-%s", k.registryPort, runtime.GOOS, runtime.GOARCH)
		steps := taskDefinition.Spec.Steps
		for i, step := range steps {
			if strings.Contains(step.Image, "/ec-cli:") {
				steps[i].Image = img
			}
		}

		out, err := yaml.Marshal(taskDefinition)
		if err != nil {
			return err
		}

		task, err := os.CreateTemp("", "v-e-c-*.yaml")
		if err != nil {
			return err
		}
		defer os.Remove(task.Name())

		if _, err = task.Write(out); err != nil {
			return err
		}

		ver := path.Base(version)

		cmd := exec.CommandContext(ctx, "make", "--no-print-directory", "-C", path.Join("..", ".."), "task-bundle", fmt.Sprintf("TASK_REPO=localhost:%d/ec-task-bundle", k.registryPort), fmt.Sprintf("TASK=%s", task.Name()), fmt.Sprintf("TASK_TAG=%s", ver))

		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Print(string(out))
			return err
		}
	}

	return nil
}
