/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"context"
	"log"

	"github.com/hacbs-contract/ec-cli/internal/applicationsnapshot"
	"github.com/hacbs-contract/ec-cli/internal/image"
	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	"github.com/spf13/cobra"
)

func k8sResourceAuthorizationCmd() *cobra.Command {
	var data = struct {
		imageRef  string
		publicKey string
		filePath  string
		input     string
		namespace string
		server    string
		spec      *appstudioshared.ApplicationSnapshotSpec
	}{}
	// k8sResourceAuthorizationCmd represents the k8sResourceAuthorization command
	cmd := &cobra.Command{
		Use:   "k8s-resource",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
		and usage of using your command. For example:

		Cobra is a CLI library for Go that empowers applications.
		This application is a tool to generate the needed files
		to quickly create a Cobra application.`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			spec, err := applicationsnapshot.DetermineInputSpec(data.filePath, data.input, data.imageRef)
			if err != nil {
				return err
			}

			data.spec = spec

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, comp := range data.spec.Components {
				err := validateK8sSource(
					cmd.Context(),
					comp.ContainerImage,
					data.publicKey,
					data.namespace,
					data.server,
				)
				if err != nil {
					log.Println(err)
					continue
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&data.publicKey, "public-key", "", "Public key")
	cmd.Flags().StringVar(&data.imageRef, "image-ref", data.imageRef, "The OCI repo to fetch the attestation from.")
	cmd.Flags().StringVarP(&data.filePath, "file-path", "f", data.filePath, "Path to ApplicationSnapshot JSON file")
	cmd.Flags().StringVarP(&data.input, "json-input", "j", data.input, "ApplicationSnapshot JSON string")
	cmd.Flags().StringVarP(&data.namespace, "namespace", "n", data.namespace, "Namespace containing the ec resource")
	cmd.Flags().StringVarP(&data.server, "server", "n", data.server, "Kubernetes server containing the ec resource")

	return cmd
}

func validateK8sSource(ctx context.Context, imageRef, publicKey, namespace, server string) error {
	k8sSource, err := image.NewK8sSource(namespace, server)
	if err != nil {
		return err
	}

	authorization, err := image.GetAuthorization(k8sSource)
	if err != nil {
		return err
	}

	imageValidator, err := image.NewImageValidator(ctx, imageRef, publicKey, "")
	if err != nil {
		return err
	}

	validatedImage, err := imageValidator.ValidateImage(ctx)
	if err != nil {
		return err
	}

	for _, att := range validatedImage.Attestations {
		// compare the authorization and attestation

	}
	return nil
}
