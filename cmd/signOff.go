/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hacbs-contract/ec-cli/internal/image"
	"github.com/spf13/cobra"
)

func signOffCmd() *cobra.Command {
	var data = struct {
		imageRef  string
		publicKey string
	}{
		imageRef:  "",
		publicKey: "",
	}
	cmd := &cobra.Command{
		Use:   "signOff",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
	and usage of using your command. For example:

	Cobra is a CLI library for Go that empowers applications.
	This application is a tool to generate the needed files
	to quickly create a Cobra application.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			imageValidator, err := image.NewImageValidator(cmd.Context(), data.imageRef, data.publicKey, "")
			if err != nil {
				return err
			}

			validatedImage, err := imageValidator.ValidateImage(cmd.Context())
			if err != nil {
				return err
			}

			for _, att := range validatedImage.Attestations {
				signoffSource, err := att.AttestationSignoffSource()
				if err != nil {
					return err
				}
				if signoffSource == nil {
					return errors.New("there is no signoff source in attestation")
				}

				signOff, _ := signoffSource.GetBuildSignOff()

				if signOff.Payload != "" {
					payload, err := json.Marshal(signOff)
					if err != nil {
						return err
					}
					fmt.Println(string(payload))
				}
			}
			return nil
		},
	}

	// attestation download options
	cmd.Flags().StringVar(&data.publicKey, "public-key", "", "Public key")
	cmd.Flags().StringVar(&data.imageRef, "image-ref", data.imageRef, "The OCI repo to fetch the attestation from.")

	return cmd
}

func init() {
	rootCmd.AddCommand(signOffCmd())

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// signOffCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// signOffCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
