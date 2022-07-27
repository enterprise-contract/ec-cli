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
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
	and usage of using your command. For example:

	Cobra is a CLI library for Go that empowers applications.
	This application is a tool to generate the needed files
	to quickly create a Cobra application.`,
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
	rootCmd.AddCommand(authorizationCmd())
}
