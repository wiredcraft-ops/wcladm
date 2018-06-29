package cmd

import (
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize components",
	Long:  `Initialize some components at Wiredcraft`,
}

func init() {
	rootCmd.AddCommand(initCmd)
}
