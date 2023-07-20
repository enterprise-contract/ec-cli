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

//go:build unit

package applicationsnapshot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	app "github.com/redhat-appstudio/application-api/api/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/enterprise-contract/ec-cli/internal/kubernetes"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

func Test_DetermineInputSpec(t *testing.T) {
	imageRef := "registry.io/repository/image:tag"
	snapshot := &app.SnapshotSpec{
		Components: []app.SnapshotComponent{
			{
				Name:           "Unnamed",
				ContainerImage: imageRef,
			},
		},
	}
	testJson, _ := json.Marshal(snapshot)
	tests := []struct {
		name  string
		input Input
		want  *app.SnapshotSpec
	}{
		{
			name:  "file",
			input: Input{File: "/home/list-of-images.json"},
			want:  snapshot,
		},
		{
			name:  "inline-json",
			input: Input{JSON: string(testJson)},
			want:  snapshot,
		},
		{
			name:  "image",
			input: Input{Image: imageRef},
			want:  snapshot,
		},
		{
			name:  "snapshot ref",
			input: Input{Snapshot: "namespace/name"},
			want:  snapshot,
		},
		{
			name:  "snapshot ref no namespace",
			input: Input{Snapshot: "just name"},
			want:  snapshot,
		},
		{
			name: "nothing",
			want: nil,
		},
		{
			name:  "snapShotSource as a string",
			input: Input{Images: string(testJson)},
			want:  snapshot,
		},
		{
			name:  "snapShotSource as a file",
			input: Input{Images: "/home/list-of-images.json"},
			want:  snapshot,
		},
		{
			name: "combined (all same)",
			input: Input{
				File:     "/home/list-of-images.json",
				JSON:     string(testJson),
				Image:    imageRef,
				Snapshot: "namespace/name",
			},
			want: snapshot,
		},
		{
			name: "combined (all different)",
			input: Input{
				File:     "/home/list-of-images.json",
				JSON:     `{"components":[{"name": "Named", "containerImage":"registry.io/repository/image:different"}]}`,
				Image:    "registry.io/repository/image:another",
				Snapshot: "namespace/name",
			},
			want: &app.SnapshotSpec{
				Components: []app.SnapshotComponent{
					snapshot.Components[0],
					{
						Name:           "Named",
						ContainerImage: "registry.io/repository/image:different",
					},
					{
						Name:           "Unnamed",
						ContainerImage: "registry.io/repository/image:another",
					},
				},
			},
		},
		{
			name: "combined (some different)",
			input: Input{
				File:  "/home/list-of-images.json",
				JSON:  `{"components":[{"name": "Named", "containerImage":"` + imageRef + `"},{"name": "Set name", "containerImage":"registry.io/repository/image:another"}]}`,
				Image: "registry.io/repository/image:another",
			},
			want: &app.SnapshotSpec{
				Components: []app.SnapshotComponent{
					{
						Name:           "Named",
						ContainerImage: imageRef,
					},
					{
						Name:           "Set name",
						ContainerImage: "registry.io/repository/image:another",
					},
				},
			},
		},
	}

	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	ctx = kubernetes.WithClient(ctx, &policy.FakeKubernetesClient{
		Snapshot: *snapshot,
	})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.input.File != "" {
				if err := afero.WriteFile(fs, tc.input.File, []byte(testJson), 0400); err != nil {
					panic(err)
				}
			}

			if tc.input.Images == "/home/list-of-images.json" {
				if err := afero.WriteFile(fs, tc.input.Images, []byte(testJson), 0400); err != nil {
					panic(err)
				}
			}

			got, err := DetermineInputSpec(ctx, tc.input)
			// expect an error so check for nil
			if tc.want != nil {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestReadSnapshotFile(t *testing.T) {

	t.Run("Successful file read and unmarshal", func(t *testing.T) {
		snapshotSpec := app.SnapshotSpec{
			Components: []app.SnapshotComponent{
				{
					Name:           "Named",
					ContainerImage: "",
				},
				{
					Name:           "Set name",
					ContainerImage: "registry.io/repository/image:another",
				},
			},
		}
		fs := afero.NewMemMapFs()
		spec := `{"components":[{"name": "Named", "containerImage":""},{"name": "Set name", "containerImage":"registry.io/repository/image:another"}]}`

		err := afero.WriteFile(fs, "/correct.json", []byte(spec), 0644)
		if err != nil {
			t.Fatalf("Setup failure: could not write file: %v", err)
		}

		content, err := afero.ReadFile(fs, "/correct.json")
		assert.NoError(t, err)
		got, err := readSnapshotSource(content)
		assert.Equal(t, snapshotSpec, got)
		assert.NoError(t, err)
	})

	t.Run("Invalid Spec", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		spec := `bad spec`
		specFile := "/badSpec.json"

		err := afero.WriteFile(fs, specFile, []byte(spec), 0644)
		if err != nil {
			t.Fatalf("Setup failure: could not write file: %v", err)
		}

		content, err := afero.ReadFile(fs, specFile)
		assert.NoError(t, err)
		_, err = readSnapshotSource(content)
		expected := errors.New("error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type v1alpha1.SnapshotSpec")
		assert.Equal(t, fmt.Errorf("unable to parse Snapshot specification from %s: %w", spec, expected), err)
	})

}
