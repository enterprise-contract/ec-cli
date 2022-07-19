package applicationsnapshot

import (
	"encoding/json"
	"errors"

	"github.com/hacbs-contract/ec-cli/internal/utils"
	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

func DetermineInputSpec(filePath string, input string, imageRef string) (*appstudioshared.ApplicationSnapshotSpec, error) {
	var appSnapshot appstudioshared.ApplicationSnapshotSpec

	// read ApplicationSnapshot provided as a file
	if len(filePath) > 0 {
		content, err := afero.ReadFile(utils.AppFS, filePath)
		if err != nil {
			log.Debugf("Problem reading application snapshot from file %s", filePath)
			return nil, err
		}

		err = json.Unmarshal(content, &appSnapshot)
		if err != nil {
			log.Debugf("Problem parsing application snapshot from file %s", filePath)
			return nil, err
		}

		log.Debugf("Read application snapshot from file %s", filePath)
		return &appSnapshot, nil
	}

	// read ApplicationSnapshot provided as a string
	if len(input) > 0 {
		// Unmarshall json into struct, exit on failure
		if err := json.Unmarshal([]byte(input), &appSnapshot); err != nil {
			log.Debugf("Problem parsing application snapshot from input param %s", input)
			return nil, err
		}

		log.Debug("Read application snapshot from input param")
		return &appSnapshot, nil
	}

	// create ApplicationSnapshot with a single image
	if len(imageRef) > 0 {
		log.Debugf("Generating application snapshot from imageRef %s", imageRef)
		return &appstudioshared.ApplicationSnapshotSpec{
			Components: []appstudioshared.ApplicationSnapshotComponent{
				{
					Name:           "Unnamed",
					ContainerImage: imageRef,
				},
			},
		}, nil
	}

	log.Debug("No application snapshot available")
	return nil, errors.New("neither ApplicationSnapshot nor image reference provided to validate")
}
