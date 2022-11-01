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

package applicationsnapshot

import (
	"encoding/json"
	"fmt"
	"testing"

	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func Test_DetermineInputSpec(t *testing.T) {
	imageRef := "quay.io://redhat-appstudio/ec"
	snapshot := &appstudioshared.ApplicationSnapshotSpec{
		Components: []appstudioshared.ApplicationSnapshotComponent{
			{
				Name:           "Unnamed",
				ContainerImage: imageRef,
			},
		},
	}
	testJson, _ := json.Marshal(snapshot)
	tests := []struct {
		filePath string
		input    string
		imageRef string
		want     *appstudioshared.ApplicationSnapshotSpec
	}{
		{
			filePath: "/home/list-of-images.json",
			input:    "",
			imageRef: "",
			want:     snapshot,
		},
		{
			filePath: "",
			input:    string(testJson),
			imageRef: "",
			want:     snapshot,
		},
		{
			filePath: "",
			input:    "",
			imageRef: imageRef,
			want:     snapshot,
		},
		{
			filePath: "",
			input:    "",
			imageRef: "",
			want:     nil,
		},
	}

	fs := afero.NewMemMapFs()

	for i, tc := range tests {
		t.Run(fmt.Sprintf("DetermineInputSpec=%d", i), func(t *testing.T) {
			if tc.filePath != "" {
				if err := afero.WriteFile(fs, tc.filePath, []byte(testJson), 0400); err != nil {
					panic(err)
				}
			}

			got, err := DetermineInputSpec(fs, tc.filePath, tc.input, tc.imageRef)
			// expect an error so check for nil
			if tc.want != nil {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}
