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

package pipeline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hacbs-contract/ec-cli/internal/utils"
	"github.com/spf13/afero"
)

var pipelineDefinitionDir = "./test_data/pipeline_definitions"

func deployPipelineFile() error {
	dirListing, err := os.ReadDir(pipelineDefinitionDir)
	if err != nil {
		return err
	}
	pipelineFiles := make([]string, 0, len(dirListing))

	for i := range dirListing {
		pipelineFiles = append(pipelineFiles, dirListing[i].Name())
	}
	for i := range pipelineFiles {
		src := filepath.Join(pipelineDefinitionDir, pipelineFiles[i])
		content, e := os.ReadFile(src)
		if e != nil {
			return e
		}
		e = afero.WriteFile(utils.AppFS, filepath.Join("/tmp/", pipelineFiles[i]), content, 0755)
		if e != nil {
			return err
		}
	}
	return nil
}

func TestDefinitionFile_exists(t *testing.T) {
	type fields struct {
		fpath string
		name  string
	}
	tests := []struct {
		name    string
		fields  fields
		want    bool
		wantErr bool
	}{
		{
			name: "Returns true if exists",
			fields: fields{
				fpath: "/tmp/pipeline.json",
			},
			want:    true,
			wantErr: false,
		},
		{
			name:    "Returns false if doesn't exist",
			fields:  fields{fpath: "/tmp/invalid-pipeline.json"},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			utils.AppFS = afero.NewMemMapFs()
			err := deployPipelineFile()
			if err != nil {
				t.Fatalf("Error setting up test \"%s\": %s", tt.name, err)
			}
			d := &DefinitionFile{
				fpath: tt.fields.fpath,
				name:  tt.fields.name,
			}
			got, err := d.exists()
			if (err != nil) != tt.wantErr {
				t.Errorf("exists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("exists() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefinitionFile_location(t *testing.T) {
	type fields struct {
		fpath string
		name  string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Returns fpath when called",
			fields: fields{
				fpath: "/tmp/pipeline.json",
				name:  "",
			},
			want: "/tmp/pipeline.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DefinitionFile{
				fpath: tt.fields.fpath,
				name:  tt.fields.name,
			}
			if got := d.location(); got != tt.want {
				t.Errorf("location() = %v, want %v", got, tt.want)
			}
		})
	}
}
