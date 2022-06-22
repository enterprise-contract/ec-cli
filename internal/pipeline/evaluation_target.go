package pipeline

import (
	"github.com/hacbs-contract/ec-cli/internal/utils"
	"github.com/spf13/afero"
)

//EvaluationTarget is an interface that represents a target to be evaluated.
//Must implement the exists() method
type EvaluationTarget interface {
	exists() (bool, error)
}

// DefinitionFile represents a file on a filesystem that defines something
type DefinitionFile struct {
	fpath string
	name  string
}

// exists returns true if the specified Definition File's fpath parameter exists on the filesystem.
func (d *DefinitionFile) exists() (bool, error) {
	return afero.Exists(utils.AppFS, d.fpath)
}
