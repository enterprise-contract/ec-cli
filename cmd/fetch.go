/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/spf13/cobra"
)

func fetchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "A subcommand to fetch various data for the enterprise contract.",
	}

	return cmd
}

func init() {
	fetch := fetchCmd()
	fetch.AddCommand(commitAuthorizationCmd())
	fetch.AddCommand(k8sResourceAuthorizationCmd())
	RootCmd.AddCommand(fetch)
}
