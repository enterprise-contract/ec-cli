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
