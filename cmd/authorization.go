/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func authorizationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authorization",
		Short: "A subcommand to retrieve various release authorizations",
		Long:  "The supported authorizations are commit and k8s sources",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("authorization called")
		},
	}

	return cmd
}

func init() {
	authorization := authorizationCmd()
	authorization.AddCommand(commitAuthorizationCmd())
	authorization.AddCommand(k8sResourceAuthorizationCmd())
	rootCmd.AddCommand(authorization)
}
