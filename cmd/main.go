package main

import (
	"fmt"
	"os"

	"github.com/sojebsikder/dns-adblocker/cmd/reload"
	"github.com/sojebsikder/dns-adblocker/cmd/server"
	"github.com/spf13/cobra"
)

var verbose bool

var RootCmd = &cobra.Command{
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use --help to see available commands.")
	},
}

func main() {
	RootCmd.AddCommand(server.ServerCmd)
	RootCmd.AddCommand(reload.ReloadCmd)
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
