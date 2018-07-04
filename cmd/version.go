package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const version = "0.0.1"

// versionCmd represents the version.go command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version info",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
