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
		resource  string
		spec      *appstudioshared.ApplicationSnapshotSpec
	}{}
	cmd := &cobra.Command{
		Use:   "k8s-resource",
		Short: "Capture signed off signatures from a k8s resource.",
		Long:  "Authorizations are defined in the enterprise contract resource.",
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
					data.resource,
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
	cmd.Flags().StringVarP(&data.server, "server", "s", data.server, "Kubernetes server containing the ec resource")
	cmd.Flags().StringVarP(&data.resource, "resource", "r", data.resource, "The ec resource holding the authorization")

	return cmd
}

func validateK8sSource(ctx context.Context, imageRef, publicKey, namespace, server, resource string) error {
	k8sSource, err := image.NewK8sSource(namespace, server, resource)
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
		err = image.PrintAuthorization(authorization, &att)
		if err != nil {
			continue
		}

	}
	return nil
}
